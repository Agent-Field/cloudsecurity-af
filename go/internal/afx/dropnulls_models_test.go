package afx

import (
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// VALIDATION CONTRACT for DumpExcludeNone on the models that actually reach it
// (VerifiedFinding, at internal/phases/prove.go and internal/phases/remediate.go,
// porting `[v.model_dump(exclude_none=True) for v in verified]` at
// src/cloudsecurity_af/reasoners/phases.py:318, :367 and :395):
//
//  1. A MODEL FIELD whose value is None is dropped (attack_path, remediation,
//     drop_reason on a finding that has none).
//  2. A None INSIDE a free-form dict field is KEPT. drift.iac_config and
//     drift.live_config are `dict[str, Any]` (schemas/recon.py:119-120), and
//     `{"logging": null}` — "not configured" — is an ordinary value the
//     drift detector emits.
//  3. An INTEGER inside such a dict stays an integer (`5432`, not `5432.0`).
//  4. A None ELEMENT of a list field survives.
//
// Ground truth, printed by the repo venv (pydantic 2.13.4) for the finding
// below:
//
//	"drift": {..., "iac_config": {"logging": null, "acl": "private",
//	                              "port": 5432},
//	                "live_config": {"logging": null}, ...}
//
// with no "attack_path", "remediation" or "drop_reason" key.

func driftedFinding() schemas.VerifiedFinding {
	return schemas.VerifiedFinding{
		ID:       "f1",
		Title:    "t",
		Verdict:  schemas.VerdictConfirmed,
		Severity: scoring.SeverityHigh,
		Category: "c",
		Drift: &schemas.DriftedResource{
			ResourceID:   "aws_s3_bucket.logs",
			ResourceType: "aws_s3_bucket",
			IaCConfig: map[string]any{
				"logging": nil,
				"acl":     "private",
				"port":    5432,
			},
			LiveConfig:   map[string]any{"logging": nil},
			Diffs:        []schemas.ConfigDiff{},
			Significance: "medium",
		},
		Resources:          []schemas.AffectedResource{},
		ComplianceMappings: []string{},
		Proof:              schemas.Proof{Method: schemas.ProofMethodStaticAnalysis, Evidence: []string{}, ScriptsExecuted: []string{}, VerificationTier: "static"},
	}
}

// Contract items 2 and 3.
func TestDumpExcludeNone_KeepsNullsInsideFreeFormDictFields(t *testing.T) {
	payload, err := DumpExcludeNone(driftedFinding())
	if err != nil {
		t.Fatalf("DumpExcludeNone: %v", err)
	}
	got := payload.Map()

	drift, ok := got["drift"].(pyfmt.Ordered)
	if !ok {
		t.Fatalf("drift = %#v, want an object", got["drift"])
	}

	iacRaw, _ := drift.Get("iac_config")
	iac, ok := iacRaw.(pyfmt.Ordered)
	if !ok {
		t.Fatalf("iac_config = %#v, want an object", iacRaw)
	}
	val, present := iac.Get("logging")
	if !present {
		t.Errorf("iac_config lost the null-valued key %q; pydantic's exclude_none keeps nulls inside dict[str, Any]", "logging")
	}
	if val != nil {
		t.Errorf("iac_config[logging] = %#v, want null", val)
	}
	if acl, _ := iac.Get("acl"); acl != "private" {
		t.Errorf("iac_config[acl] = %#v", acl)
	}
	if port, _ := iac.Get("port"); port != 5432 {
		t.Errorf("iac_config[port] = %#v, want the integer 5432 (Python renders 5432, not 5432.0)", port)
	}

	liveRaw, _ := drift.Get("live_config")
	live, ok := liveRaw.(pyfmt.Ordered)
	if !ok {
		t.Fatalf("live_config = %#v, want an object", liveRaw)
	}
	if _, present := live.Get("logging"); !present {
		t.Errorf("live_config lost its null-valued key; got %#v", live)
	}
}

// Contract item 1 — the half that must keep working.
func TestDumpExcludeNone_StillDropsNilModelFields(t *testing.T) {
	payload, err := DumpExcludeNone(driftedFinding())
	if err != nil {
		t.Fatalf("DumpExcludeNone: %v", err)
	}
	got := payload.Map()
	for _, key := range []string{"attack_path", "remediation", "drop_reason"} {
		if _, present := got[key]; present {
			t.Errorf("%q survived exclude_none; pydantic drops a None MODEL field", key)
		}
	}
	// A non-nil model field is kept and recursed into: security_impact is a
	// *string on ConfigDiff, so a diff with none must lose that key only.
	f := driftedFinding()
	f.Drift.Diffs = []schemas.ConfigDiff{{Attribute: "acl", IaCValue: "private", LiveValue: nil}}
	payload, err = DumpExcludeNone(f)
	if err != nil {
		t.Fatalf("DumpExcludeNone: %v", err)
	}
	driftRaw, _ := payload.Get("drift")
	diffsRaw, _ := driftRaw.(pyfmt.Ordered).Get("diffs")
	diff := diffsRaw.([]any)[0].(pyfmt.Ordered)
	if _, present := diff.Get("security_impact"); present {
		t.Error("security_impact is a None model field and must be dropped")
	}
	if _, present := diff.Get("live_value"); present {
		t.Error("live_value is `Any = None`, i.e. a None MODEL field, and must be dropped")
	}
	if v, _ := diff.Get("iac_value"); v != "private" {
		t.Errorf("iac_value = %#v", v)
	}
}

// Contract item 4 — a None element of a list field is not a model field.
func TestDumpExcludeNone_KeepsNullListElements(t *testing.T) {
	type inner struct {
		A *string `json:"a"`
		B string  `json:"b"`
	}
	type outer struct {
		List []*inner       `json:"lst"`
		Dict map[string]any `json:"d"`
	}
	got, err := DumpExcludeNone(outer{
		List: []*inner{{B: "x"}, nil},
		Dict: map[string]any{"k": nil, "j": 1},
	})
	if err != nil {
		t.Fatalf("DumpExcludeNone: %v", err)
	}
	lstRaw, _ := got.Get("lst")
	lst, _ := lstRaw.([]any)
	if len(lst) != 2 || lst[1] != nil {
		t.Errorf("lst = %#v, want the null element kept (pydantic: [{'b':'x'}, None])", lst)
	}
	first, _ := lst[0].(pyfmt.Ordered)
	if _, present := first.Get("a"); present {
		t.Error("the nested model's None field must still be dropped")
	}
	dRaw, _ := got.Get("d")
	d, _ := dRaw.(pyfmt.Ordered)
	if _, present := d.Get("k"); !present {
		t.Errorf("d = %#v, want the null value kept (pydantic: {'k': None, 'j': 1})", d)
	}
}
