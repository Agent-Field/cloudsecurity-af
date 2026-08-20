package schemas

import (
	"reflect"
	"sort"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
)

// VALIDATION CONTRACT for required.go: for every ported model,
//
//	Model.RequiredFields() == [n for n, f in Model.model_fields.items()
//	                           if f.is_required()]
//
// which is exactly the `required` array pydantic writes into
// `Model.model_json_schema()` — i.e. into the committed fixtures under
// internal/harnessx/testdata/schemas/, which scripts/gen_schemas.py generates
// from the live Python models. Cross-checking against those fixtures means a
// Python schema change that regenerates them fails HERE instead of silently
// loosening every `Model.model_validate(payload)` in the port.
//
// The lists that no fixture covers were read off the live models under the repo
// venv and are pinned by TestRequiredFields_LiveModelTranscription below.

func TestRequiredFields_MatchTheCommittedPydanticSchemas(t *testing.T) {
	registry := goDefaults()

	names := harnessx.EmbeddedSchemaNames()
	if len(names) == 0 {
		t.Fatal("no embedded schema fixtures found")
	}

	checked := 0
	for _, fixture := range names {
		schema, err := harnessx.LoadEmbeddedSchema(fixture)
		if err != nil {
			t.Fatalf("LoadEmbeddedSchema(%s): %v", fixture, err)
		}
		checkRequiredAgainstSchema(t, registry, fixture, schema)
		checked++

		defs, _ := schema["$defs"].(map[string]any)
		for defName, raw := range defs {
			sub, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if _, hasProps := sub["properties"]; !hasProps {
				continue // an enum or scalar $def, not a model
			}
			checkRequiredAgainstSchema(t, registry, defName, sub)
			checked++
		}
	}
	if checked < len(names) {
		t.Errorf("cross-checked %d models from %d fixtures", checked, len(names))
	}
}

// checkRequiredAgainstSchema compares one schema node's `required` array with
// the Go model's RequiredFields.
func checkRequiredAgainstSchema(t *testing.T, registry map[string]any, name string, node map[string]any) {
	t.Helper()

	model, present := registry[name]
	if !present {
		t.Errorf("no Go model registered for schema %q", name)
		return
	}

	want := make([]string, 0)
	if raw, ok := node["required"].([]any); ok {
		for _, v := range raw {
			s, ok := v.(string)
			if !ok {
				t.Errorf("%s: required entry %#v is not a string", name, v)
				continue
			}
			want = append(want, s)
		}
	}

	var got []string
	if rf, ok := model.(afx.RequiredFielder); ok {
		got = append(got, rf.RequiredFields()...)
	}

	sortedWant := append([]string(nil), want...)
	sortedGot := append([]string(nil), got...)
	sort.Strings(sortedWant)
	sort.Strings(sortedGot)
	if !reflect.DeepEqual(sortedWant, sortedGot) {
		t.Errorf("%s.RequiredFields() = %v, want %v (the fixture's \"required\" array)", name, got, want)
	}
}

// TestRequiredFields_LiveModelTranscription pins the lists for the models that
// no harness fixture covers. The expectations were produced under the repo venv
// with
//
//	[n for n, f in Model.model_fields.items() if f.is_required()]
//
// over every class in src/cloudsecurity_af/schemas/*.py.
func TestRequiredFields_LiveModelTranscription(t *testing.T) {
	want := map[string][]string{
		"Variable":                {"name"},
		"Output":                  {"name"},
		"ProviderConfig":          {"name"},
		"Module":                  {"name", "source"},
		"Resource":                {"id", "type", "name", "provider", "file_path"},
		"ResourceInventory":       {"inventory_saved_path"},
		"ResourceGraph":           {"graph_saved_path"},
		"ConfigDiff":              {"attribute"},
		"DriftedResource":         {"resource_id", "resource_type"},
		"DriftReport":             nil,
		"ReconResult":             nil,
		"AffectedResource":        {"resource_id", "resource_type", "attribute"},
		"RawFinding":              {"hunter_strategy", "title", "description", "category"},
		"HuntResult":              nil,
		"AttackStep":              {"step_number", "resource_id", "resource_type", "action", "permission_used"},
		"BlastRadius":             nil,
		"AttackPath":              {"title", "description", "entry_point", "target"},
		"ChainResult":             nil,
		"Proof":                   nil,
		"IaCDiff":                 {"file_path", "original_lines", "patched_lines"},
		"RemediationSuggestion":   {"description"},
		"VerifiedFinding":         {"title", "verdict", "severity", "category"},
		"CloudConfig":             nil,
		"CloudSecurityInput":      {"repo_url"},
		"CloudSecurityScanResult": {"repository", "commit_sha", "timestamp", "depth_profile", "tier"},
		"ScanProgress": {"phase", "phase_progress", "agents_total", "agents_completed", "agents_running",
			"findings_so_far", "elapsed_seconds", "estimated_remaining_seconds", "cost_so_far_usd"},
		"ScanMetrics":      {"duration_seconds", "agent_invocations", "cost_usd"},
		"FindingForDedup":  {"id", "fingerprint", "title", "iac_file", "iac_line", "category", "hunter_strategy", "estimated_severity"},
		"FindingForProver": {"id", "title", "description", "category", "hunter_strategy", "iac_file", "iac_line", "config_snippet"},
		"FindingForChain":  {"id", "title", "description", "category"},
		// agents/chain/path_constructor.py — kept in schemas per DESIGN §2c.
		"ChildInvestigation":    {"title", "child_prompt"},
		"PathInvestigationPlan": nil,
	}

	registry := goDefaults()
	for name, model := range registry {
		expected, known := want[name]
		if !known {
			t.Errorf("model %q has no transcription in this test; add it (and its RequiredFields, if any)", name)
			continue
		}
		var got []string
		if rf, ok := model.(afx.RequiredFielder); ok {
			got = rf.RequiredFields()
		}
		if len(expected) == 0 && len(got) != 0 {
			t.Errorf("%s.RequiredFields() = %v, want none (every field has a pydantic default)", name, got)
			continue
		}
		if len(expected) != 0 && !reflect.DeepEqual(got, expected) {
			t.Errorf("%s.RequiredFields() = %v, want %v", name, got, expected)
		}
	}
	for name := range want {
		if _, present := registry[name]; !present {
			t.Errorf("goDefaults has no entry for %q", name)
		}
	}
}

// The behaviour required.go exists for: `Model.model_validate(payload)` must
// RAISE for a payload missing a required field, not return a zero-valued model.
func TestRequiredFields_BindRaisesLikeModelValidate(t *testing.T) {
	// recon_phase: ResourceInventory.model_validate on the iac-reader reply.
	if _, err := afx.Bind[ResourceInventory](map[string]any{"total_resources": 3}); err == nil {
		t.Error("Bind[ResourceInventory] accepted a payload with no inventory_saved_path; pydantic raises 'Field required'")
	}
	if _, err := afx.Bind[ResourceInventory](map[string]any{"inventory_saved_path": "/tmp/i.json"}); err != nil {
		t.Errorf("Bind[ResourceInventory] rejected a valid payload: %v", err)
	}

	// prove_phase: VerifiedFinding.model_validate on the prover reply.
	if _, err := afx.Bind[VerifiedFinding](map[string]any{"id": "f1"}); err == nil {
		t.Error("Bind[VerifiedFinding] accepted a payload with no title/verdict/severity/category")
	}

	// Nested models are validated too, exactly as pydantic does.
	if _, err := afx.Bind[VerifiedFinding](map[string]any{
		"title": "t", "verdict": "confirmed", "severity": "high", "category": "c",
		"resources": []any{map[string]any{"resource_id": "r"}},
	}); err == nil {
		t.Error("Bind[VerifiedFinding] accepted a nested AffectedResource missing resource_type/attribute")
	}

	// A model whose fields ALL have defaults still binds from {}.
	if _, err := afx.Bind[DriftReport](map[string]any{}); err != nil {
		t.Errorf("Bind[DriftReport]({}) must succeed — every field has a default: %v", err)
	}
}
