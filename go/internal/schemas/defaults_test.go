package schemas

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// This file pins the default-seeding contract itself (doc.go): an ABSENT key
// keeps the pydantic default, while a PRESENT key overrides it even when the
// value is the Go zero value. Every expectation below was verified against
// ~/.agentfield/packages/cloudsecurity-af/venv/bin/python.

// TestSeeding_AbsentKeyKeepsDefault_PresentKeyOverrides walks the models whose
// non-zero defaults would silently vanish under a plain json.Unmarshal.
func TestSeeding_AbsentKeyKeepsDefault_PresentKeyOverrides(t *testing.T) {
	t.Run("CloudConfig", func(t *testing.T) {
		// Python: CloudConfig.model_validate({"regions": []}) ->
		//   {'provider': 'aws', 'regions': [], ...}
		var c CloudConfig
		if err := json.Unmarshal([]byte(`{"regions":[]}`), &c); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if c.Provider != "aws" {
			t.Errorf("absent provider = %q, want aws", c.Provider)
		}
		if c.Regions == nil || len(c.Regions) != 0 {
			t.Errorf("explicit empty regions = %v, want [] (not the default)", c.Regions)
		}
		// Python: CloudConfig.model_validate({"provider": ""}) keeps regions.
		if err := json.Unmarshal([]byte(`{"provider":""}`), &c); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if c.Provider != "" {
			t.Errorf("explicit empty provider = %q, want \"\"", c.Provider)
		}
		if !reflect.DeepEqual(c.Regions, []string{"us-east-1"}) {
			t.Errorf("regions = %v, want the default [us-east-1]", c.Regions)
		}
	})

	t.Run("CloudSecurityInput", func(t *testing.T) {
		var in CloudSecurityInput
		if err := json.Unmarshal([]byte(`{"repo_url":"x","exclude_paths":[],"branch":"","include_paths":[]}`), &in); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if in.Branch != "" {
			t.Errorf("explicit empty branch = %q", in.Branch)
		}
		if in.ExcludePaths == nil || len(in.ExcludePaths) != 0 {
			t.Errorf("explicit empty exclude_paths = %v, want []", in.ExcludePaths)
		}
		// Python: include_paths=[] dumps as [], include_paths absent dumps as null.
		if in.IncludePaths == nil || len(in.IncludePaths) != 0 {
			t.Errorf("explicit empty include_paths = %v, want []", in.IncludePaths)
		}
		var bare CloudSecurityInput
		if err := json.Unmarshal([]byte(`{"repo_url":"x"}`), &bare); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got := mustJSONMap(t, bare)
		if got["include_paths"] != nil {
			t.Errorf("absent include_paths marshals as %v, want null", got["include_paths"])
		}
		if in.SeverityThreshold != "low" || in.Depth != "standard" {
			t.Errorf("threshold/depth = %q/%q, want low/standard", in.SeverityThreshold, in.Depth)
		}
		if !reflect.DeepEqual(bare.OutputFormats, []string{"json"}) {
			t.Errorf("output_formats = %v, want [json]", bare.OutputFormats)
		}
	})

	t.Run("Proof", func(t *testing.T) {
		// Python: Proof.model_validate({"verification_tier": ""}) ->
		//   {'method': 'static_analysis', ..., 'verification_tier': ''}
		var p Proof
		if err := json.Unmarshal([]byte(`{"verification_tier":""}`), &p); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if p.Method != ProofMethodStaticAnalysis {
			t.Errorf("method = %q, want static_analysis", p.Method)
		}
		if p.VerificationTier != "" {
			t.Errorf("explicit empty verification_tier = %q", p.VerificationTier)
		}
		if p.Evidence == nil || p.ScriptsExecuted == nil {
			t.Error("evidence/scripts_executed must be non-nil empty slices")
		}
	})

	t.Run("RemediationSuggestion", func(t *testing.T) {
		// Python: RemediationSuggestion.model_validate({"description":"d","effort":""})
		//   -> effort '' (explicit empty overrides "moderate").
		var r RemediationSuggestion
		if err := json.Unmarshal([]byte(`{"description":"d","effort":""}`), &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if r.Effort != "" {
			t.Errorf("explicit empty effort = %q", r.Effort)
		}
		if err := json.Unmarshal([]byte(`{"description":"d"}`), &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if r.Effort != "moderate" {
			t.Errorf("absent effort = %q, want moderate", r.Effort)
		}
	})

	t.Run("DriftedResource", func(t *testing.T) {
		// Python: significance '' when explicitly empty, 'medium' when absent.
		var d DriftedResource
		if err := json.Unmarshal([]byte(`{"resource_id":"r","resource_type":"t","significance":""}`), &d); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if d.Significance != "" {
			t.Errorf("explicit empty significance = %q", d.Significance)
		}
		if err := json.Unmarshal([]byte(`{"resource_id":"r","resource_type":"t"}`), &d); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if d.Significance != "medium" {
			t.Errorf("absent significance = %q, want medium", d.Significance)
		}
		got := mustJSONMap(t, d)
		if !reflect.DeepEqual(got["iac_config"], map[string]any{}) {
			t.Errorf("iac_config = %v, want {}", got["iac_config"])
		}
	})

	t.Run("AttackPath", func(t *testing.T) {
		var a AttackPath
		if err := json.Unmarshal([]byte(`{"title":"t","description":"d","entry_point":"e","target":"g"}`), &a); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if a.CombinedSeverity != scoring.SeverityHigh {
			t.Errorf("absent combined_severity = %q, want high", a.CombinedSeverity)
		}
		if a.ID == "" {
			t.Error("absent id should be filled by the uuid4 default_factory")
		}
		if a.BlastRadius.DataStoresReachable == nil {
			t.Error("nested BlastRadius must re-seed its own list defaults")
		}
		if err := json.Unmarshal([]byte(`{"title":"t","combined_severity":"low","id":"fixed"}`), &a); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if a.CombinedSeverity != scoring.SeverityLow || a.ID != "fixed" {
			t.Errorf("explicit values not applied: %q / %q", a.CombinedSeverity, a.ID)
		}
	})

	t.Run("RawFinding", func(t *testing.T) {
		// Python ground truth (venv):
		//   RawFinding.model_validate({... , "estimated_severity":"critical",
		//     "confidence":"low", "iac_line":7, "id":"fixed", "fingerprint":"fp"})
		payload := `{"hunter_strategy":"iam","title":"t","description":"d","category":"c",` +
			`"id":"fixed","fingerprint":"fp","estimated_severity":"critical","confidence":"low","iac_line":7}`
		var f RawFinding
		if err := json.Unmarshal([]byte(payload), &f); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		want := map[string]any{
			"benchmark_id":       nil,
			"category":           "c",
			"confidence":         "low",
			"config_snippet":     "",
			"description":        "d",
			"estimated_severity": "critical",
			"fingerprint":        "fp",
			"hunter_strategy":    "iam",
			"iac_file":           "",
			"iac_line":           float64(7),
			"id":                 "fixed",
			"resources":          []any{},
			"title":              "t",
		}
		if got := mustJSONMap(t, f); !reflect.DeepEqual(got, want) {
			gj, _ := json.MarshalIndent(got, "", "  ")
			wj, _ := json.MarshalIndent(want, "", "  ")
			t.Errorf("dump mismatch\n go:     %s\n python: %s", gj, wj)
		}
	})

	t.Run("ReconResult", func(t *testing.T) {
		// Python ground truth (venv), nested defaults re-seeded by the sub-models.
		payload := `{"inventory":{"inventory_saved_path":"/a"},"resource_graph":{"graph_saved_path":"/b"},"providers_detected":["aws"]}`
		var r ReconResult
		if err := json.Unmarshal([]byte(payload), &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		want := map[string]any{
			"drift_report": nil,
			"iac_type":     "terraform",
			"inventory": map[string]any{
				"iac_type": "terraform", "iac_version": nil,
				"inventory_saved_path": "/a", "total_resources": float64(0),
			},
			"live_inventory":         nil,
			"providers_detected":     []any{"aws"},
			"recon_duration_seconds": float64(0),
			"resource_graph": map[string]any{
				"graph_saved_path": "/b", "total_edges": float64(0), "total_nodes": float64(0),
			},
			"total_edges":     float64(0),
			"total_resources": float64(0),
		}
		if got := mustJSONMap(t, r); !reflect.DeepEqual(got, want) {
			gj, _ := json.MarshalIndent(got, "", "  ")
			wj, _ := json.MarshalIndent(want, "", "  ")
			t.Errorf("dump mismatch\n go:     %s\n python: %s", gj, wj)
		}
	})
}

// TestSeeding_UUIDDefaultsAreFreshPerDecode mirrors pydantic: the
// default_factory runs on every model_validate that omits the key, so two
// decodes of the same id-less payload produce different ids.
func TestSeeding_UUIDDefaultsAreFreshPerDecode(t *testing.T) {
	payload := []byte(`{"hunter_strategy":"iam","title":"t","description":"d","category":"c"}`)
	var a, b RawFinding
	if err := json.Unmarshal(payload, &a); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	if err := json.Unmarshal(payload, &b); err != nil {
		t.Fatalf("unmarshal b: %v", err)
	}
	if a.ID == b.ID {
		t.Errorf("two decodes produced the same id %q; the uuid4 default_factory must run per decode", a.ID)
	}
	if a.ID == a.Fingerprint {
		t.Error("id and fingerprint use separate default_factory calls and must differ")
	}
}

// TestSeeding_EmptySlicesNeverMarshalAsNull sweeps every constructor and asserts
// no default_factory=list / dict field marshals as null.
func TestSeeding_EmptySlicesNeverMarshalAsNull(t *testing.T) {
	python := loadPythonModels(t)
	for name, value := range goDefaults() {
		want, ok := python[name]
		if !ok {
			continue
		}
		var wantMap map[string]any
		if err := json.Unmarshal(want.Dump, &wantMap); err != nil {
			t.Fatalf("%s: decode fixture: %v", name, err)
		}
		got := mustJSONMap(t, value)
		for key, wv := range wantMap {
			switch wv.(type) {
			case []any, map[string]any:
				if got[key] == nil {
					t.Errorf("%s.%s marshals as null but Python emits %T", name, key, wv)
				}
			}
		}
	}
}

// TestStrictEnumDecoding pins the pydantic-parity rejection of unknown enum
// members and nulls inside a model payload. Verified against the interpreter:
// both `"estimated_severity": "bogus"` and `"estimated_severity": None` raise
// ValidationError.
func TestStrictEnumDecoding(t *testing.T) {
	base := `{"hunter_strategy":"iam","title":"t","description":"d","category":"c"`
	cases := []struct {
		name    string
		payload string
		wantErr bool
	}{
		{"valid severity", base + `,"estimated_severity":"critical"}`, false},
		{"unknown severity", base + `,"estimated_severity":"bogus"}`, true},
		{"null severity", base + `,"estimated_severity":null}`, true},
		{"uppercase confidence", base + `,"confidence":"HIGH"}`, true},
		{"valid confidence", base + `,"confidence":"low"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var f RawFinding
			err := json.Unmarshal([]byte(c.payload), &f)
			if c.wantErr && err == nil {
				t.Error("want a decode error (pydantic ValidationError parity), got nil")
			}
			if !c.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	t.Run("unknown verdict", func(t *testing.T) {
		var v VerifiedFinding
		if err := json.Unmarshal([]byte(`{"title":"t","verdict":"maybe","severity":"high","category":"c"}`), &v); err == nil {
			t.Error("want a decode error for an unknown Verdict")
		}
	})
	t.Run("unknown proof method", func(t *testing.T) {
		var p Proof
		if err := json.Unmarshal([]byte(`{"method":"vibes"}`), &p); err == nil {
			t.Error("want a decode error for an unknown ProofMethod")
		}
	})
}

// TestUnknownKeysAreIgnored mirrors pydantic's default `extra='ignore'`:
// verified that RawFinding.model_validate({..., "zzz": 1}) succeeds and "zzz"
// is absent from model_dump().
func TestUnknownKeysAreIgnored(t *testing.T) {
	var f RawFinding
	payload := `{"hunter_strategy":"iam","title":"t","description":"d","category":"c","zzz":1}`
	if err := json.Unmarshal([]byte(payload), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := mustJSONMap(t, f)["zzz"]; ok {
		t.Error("unknown key leaked into the dump")
	}
}
