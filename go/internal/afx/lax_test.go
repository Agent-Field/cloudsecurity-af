package afx

import (
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// VALIDATION CONTRACT for the pydantic-lax half of afx.Bind (lax.go).
//
// Every expectation below was measured against the repo venv (pydantic 2.13.4,
// ~/.agentfield/packages/cloudsecurity-af/venv/bin/python, PYTHONPATH=src) by
// calling the REAL models. Transcript, abridged to the rows the tables use:
//
//	RawFinding.iac_line (int):
//	  "12" -> 12   " 12 " -> 12   "+12"/"-12" -> 12/-12   "012" -> 12
//	  "1_000" -> 1000   "12.0" -> 12   12.0 -> 12   True/False -> 1/0
//	  "12." / "12.5" / "2e2" / "0x10" / "abc" / "" -> ERR int_parsing
//	  12.5 -> ERR int_from_float      None -> ERR int_type
//	VerifiedFinding.risk_score (float):
//	  "5.5" -> 5.5   " 5.5 " -> 5.5   "5" -> 5.0   "+5.5" -> 5.5
//	  ".5" -> 0.5   "5." -> 5.0   "1e3" -> 1000.0   "1_0.5" -> 10.5
//	  5 -> 5.0   True -> 1.0
//	  "" / "abc" -> ERR float_parsing     None -> ERR float_type
//	DriftedResource.security_relevant (bool):
//	  1/0 -> True/False        1.0/0.0 -> True/False
//	  "true","True","TRUE","yes","on","1","t","y" -> True
//	  "false","no","off","0","f","n"              -> False
//	  2 / -1 -> ERR bool_parsing   1.5 -> ERR bool_type   None -> ERR bool_type
//	RawFinding.title (str):
//	  5 / 5.5 / True / None -> ERR string_type  (pydantic does NOT stringify)
//	Nulls:
//	  RawFinding{"resources": null}             -> ERR
//	  RawFinding{"iac_line": null}              -> ERR
//	  Proof{"evidence": null}                   -> ERR
//	  VerifiedFinding{"compliance_mappings": null} -> ERR
//	  RawFinding{"benchmark_id": null}          -> OK   (`str | None`)
//	  CloudSecurityInput{"include_paths": null} -> OK   (`list[str] | None`)
//	  RawFinding{"confidence": null}            -> ERR  (already: strict enum)

func rawFindingBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"hunter_strategy": "iam",
		"title":           "t",
		"description":     "d",
		"category":        "c",
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func verifiedFindingBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"title":    "t",
		"verdict":  "confirmed",
		"severity": "medium",
		"category": "c",
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// CONTRACT 1 — a value pydantic's lax mode coerces must bind, not 422.
//
// This is the finding-losing case: the Go SDK's harness validates a model reply
// with a plain json.Unmarshal, so a hunter that writes `"iac_line": "12"` used
// to burn the schema-retry budget and end as `iam_hunter harness error: ...`,
// which hunt_phase swallows into an EMPTY batch — that hunter contributes zero
// findings where the Python node contributes all of them.
func TestBind_CoercesTheScalarsPydanticCoerces(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		cases := []struct {
			in   any
			want int
		}{
			{"12", 12}, {" 12 ", 12}, {"+12", 12}, {"-12", -12}, {"012", 12},
			{"1_000", 1000}, {"12.0", 12}, {12.0, 12}, {true, 1}, {false, 0},
		}
		for _, tc := range cases {
			got, err := Bind[schemas.RawFinding](rawFindingBody(map[string]any{"iac_line": tc.in}))
			if err != nil {
				t.Fatalf("iac_line=%#v: %v", tc.in, err)
			}
			if got.IaCLine != tc.want {
				t.Errorf("iac_line=%#v -> %d, want %d", tc.in, got.IaCLine, tc.want)
			}
		}
	})

	t.Run("float", func(t *testing.T) {
		cases := []struct {
			in   any
			want float64
		}{
			{"5.5", 5.5}, {" 5.5 ", 5.5}, {"5", 5}, {"+5.5", 5.5}, {".5", 0.5},
			{"5.", 5}, {"1e3", 1000}, {"1_0.5", 10.5}, {5, 5}, {true, 1},
		}
		for _, tc := range cases {
			got, err := Bind[schemas.VerifiedFinding](verifiedFindingBody(map[string]any{"risk_score": tc.in}))
			if err != nil {
				t.Fatalf("risk_score=%#v: %v", tc.in, err)
			}
			if got.RiskScore != tc.want {
				t.Errorf("risk_score=%#v -> %v, want %v", tc.in, got.RiskScore, tc.want)
			}
		}
	})

	t.Run("bool", func(t *testing.T) {
		cases := []struct {
			in   any
			want bool
		}{
			{1, true}, {0, false}, {1.0, true}, {0.0, false},
			{"true", true}, {"True", true}, {"TRUE", true}, {"yes", true},
			{"on", true}, {"1", true}, {"t", true}, {"y", true},
			{"false", false}, {"no", false}, {"off", false}, {"0", false},
			{"f", false}, {"n", false},
		}
		for _, tc := range cases {
			got, err := Bind[schemas.DriftedResource](map[string]any{
				"resource_id": "r", "resource_type": "t", "security_relevant": tc.in,
			})
			if err != nil {
				t.Fatalf("security_relevant=%#v: %v", tc.in, err)
			}
			if got.SecurityRelevant != tc.want {
				t.Errorf("security_relevant=%#v -> %v, want %v", tc.in, got.SecurityRelevant, tc.want)
			}
		}
	})
}

// CONTRACT 2 — the ladder must not become a general "accept anything". Every
// row here is a pydantic ValidationError, so the bind must fail too.
func TestBind_RejectsTheScalarsPydanticRejects(t *testing.T) {
	intCases := []any{12.5, "12.", "12.5", "2e2", "0x10", "abc", "", []any{1}}
	for _, in := range intCases {
		if _, err := Bind[schemas.RawFinding](rawFindingBody(map[string]any{"iac_line": in})); err == nil {
			t.Errorf("iac_line=%#v bound; pydantic raises", in)
		}
	}
	floatCases := []any{"", "abc"}
	for _, in := range floatCases {
		if _, err := Bind[schemas.VerifiedFinding](verifiedFindingBody(map[string]any{"risk_score": in})); err == nil {
			t.Errorf("risk_score=%#v bound; pydantic raises", in)
		}
	}
	boolCases := []any{2, -1, 1.5, "", "abc"}
	for _, in := range boolCases {
		if _, err := Bind[schemas.DriftedResource](map[string]any{
			"resource_id": "r", "resource_type": "t", "security_relevant": in,
		}); err == nil {
			t.Errorf("security_relevant=%#v bound; pydantic raises", in)
		}
	}
	// pydantic v2 does NOT stringify a number/bool for a `str` field.
	for _, in := range []any{5, 5.5, true} {
		if _, err := Bind[schemas.RawFinding](rawFindingBody(map[string]any{"title": in})); err == nil {
			t.Errorf("title=%#v bound; pydantic raises string_type", in)
		}
	}
}

// CONTRACT 3 — an explicit null for a field that is not `X | None` is a
// pydantic ValidationError. encoding/json treats null as a no-op for a scalar
// and as "set to nil" for a slice, so without lax.go the seeded default
// survived (iac_line stayed 0) or the seeded `[]` was wiped back to null.
func TestBind_RejectsNullForANonOptionalField(t *testing.T) {
	if _, err := Bind[schemas.RawFinding](rawFindingBody(map[string]any{"resources": nil})); err == nil {
		t.Error("resources=null bound; pydantic raises list_type")
	} else if got := err.Error(); !strings.Contains(got, "RawFinding: resources: Input should be a valid list") {
		t.Errorf("err = %q", got)
	}
	if _, err := Bind[schemas.RawFinding](rawFindingBody(map[string]any{"iac_line": nil})); err == nil {
		t.Error("iac_line=null bound; pydantic raises int_type")
	}
	if _, err := Bind[schemas.Proof](map[string]any{"evidence": nil}); err == nil {
		t.Error("evidence=null bound; pydantic raises list_type")
	}
	if _, err := Bind[schemas.VerifiedFinding](verifiedFindingBody(map[string]any{"compliance_mappings": nil})); err == nil {
		t.Error("compliance_mappings=null bound; pydantic raises list_type")
	}
	// Nested: the rule follows a model into a list of models.
	if _, err := Bind[schemas.HuntResult](map[string]any{
		"findings": []any{rawFindingBody(map[string]any{"resources": nil})},
	}); err == nil {
		t.Error("findings[0].resources=null bound; pydantic raises")
	}
}

// CONTRACT 4 — the mirror image: a null the Python node ACCEPTS must still
// bind, or the rule would break every `X | None` field in the port.
func TestBind_AcceptsNullForAnOptionalField(t *testing.T) {
	got, err := Bind[schemas.RawFinding](rawFindingBody(map[string]any{"benchmark_id": nil}))
	if err != nil {
		t.Fatalf("benchmark_id=null: %v", err)
	}
	if got.BenchmarkID != nil {
		t.Errorf("benchmark_id = %v, want nil", *got.BenchmarkID)
	}
	// include_paths is the ONE `X | None` field that is not a Go pointer; the
	// exception is declared by CloudSecurityInput.NullableFields.
	in, err := Bind[schemas.CloudSecurityInput](map[string]any{"repo_url": "/r", "include_paths": nil})
	if err != nil {
		t.Fatalf("include_paths=null: %v", err)
	}
	if in.IncludePaths != nil {
		t.Errorf("include_paths = %v, want nil", in.IncludePaths)
	}
	// A null inside a free-form `dict[str, Any]` is an ordinary value.
	drift, err := Bind[schemas.DriftedResource](map[string]any{
		"resource_id": "r", "resource_type": "t",
		"iac_config": map[string]any{"logging": nil},
	})
	if err != nil {
		t.Fatalf("iac_config={logging: null}: %v", err)
	}
	if v, ok := drift.IaCConfig["logging"]; !ok || v != nil {
		t.Errorf("iac_config = %#v, want the null preserved", drift.IaCConfig)
	}
}

// CONTRACT 5 — the rules are for MODELS only. A reasoner input struct stands
// for a Python function signature, whose validation is
// Agent._validate_handler_input (handlerinput.go), and there `drift_report:
// null` is simply the parameter's default None, not an error.
func TestBind_LeavesReasonerInputStructsAlone(t *testing.T) {
	type chainPhaseInputLike struct {
		Findings          []any          `json:"findings"`
		ResourceGraphPath string         `json:"resource_graph_path"`
		DriftReport       map[string]any `json:"drift_report"`
	}
	got, err := Bind[chainPhaseInputLike](map[string]any{
		"findings":            []any{1, 2, "x"},
		"resource_graph_path": "/g",
		"drift_report":        nil,
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if len(got.Findings) != 3 || got.DriftReport != nil {
		t.Fatalf("got = %#v", got)
	}
}
