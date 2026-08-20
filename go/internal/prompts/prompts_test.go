package prompts

import (
	"reflect"
	"strings"
	"testing"
)

// The template set is a cross-package contract: the agent packages reference
// these paths as constants, so an accidental rename must fail loudly here
// rather than at runtime inside a reasoner.
func TestNames_IsTheFullPythonPromptTree(t *testing.T) {
	want := []string{
		"chain/path_constructor.txt",
		"hunt/compliance.txt",
		"hunt/compute.txt",
		"hunt/data.txt",
		"hunt/iam.txt",
		"hunt/logging.txt",
		"hunt/network.txt",
		"hunt/secrets.txt",
		"prove/live_prover.txt",
		"prove/static_prover.txt",
		"recon/cloud_connector.txt",
		"recon/drift_detector.txt",
		"recon/iac_reader.txt",
		"recon/resource_graph_builder.txt",
		"remediate/fix_generator.txt",
	}
	if got := Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Names() = %#v, want %#v", got, want)
	}
}

func TestLoad_ReturnsNonEmptyTemplates(t *testing.T) {
	for _, name := range Names() {
		body, err := Load(name)
		if err != nil {
			t.Fatalf("Load(%q): %v", name, err)
		}
		if strings.TrimSpace(body) == "" {
			t.Errorf("Load(%q) is blank", name)
		}
	}
}

func TestLoad_MissingTemplateIsAnError(t *testing.T) {
	if _, err := Load("recon/nope.txt"); err == nil {
		t.Fatal("expected an error for a missing template")
	}
	// A traversal attempt must not escape the embedded tree.
	if _, err := Load("../../../src/cloudsecurity_af/app.py"); err == nil {
		t.Fatal("expected an error for a path outside the prompts root")
	}
}

func TestMustLoad_PanicsOnAMissingTemplate(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustLoad did not panic")
		}
	}()
	_ = MustLoad("nope/nope.txt")
}

func TestMustLoad_ReturnsTheSameBytesAsLoad(t *testing.T) {
	want, err := Load("recon/iac_reader.txt")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := MustLoad("recon/iac_reader.txt"); got != want {
		t.Fatal("MustLoad and Load disagree")
	}
}

// ---------------------------------------------------------------------------
// Ports tests/test_utils.py::TestPromptTemplatesExist and
// ::TestHuntPromptPlaceholders — WITH A CORRECTED PROMPT ROOT.
//
// Both Python classes resolve PROMPT_ROOT as
// `Path(__file__).resolve().parents[1] / "prompts"`, i.e. <repo>/prompts. That
// directory NO LONGER EXISTS — the templates were moved into the package at
// src/cloudsecurity_af/prompts (which is what every agent's PROMPT_PATH,
// `parents[2] / "prompts" / ...`, actually reads), so those Python tests fail
// on main today. The Go port checks the templates the runtime really loads.
// ---------------------------------------------------------------------------

// Ports TestPromptTemplatesExist::test_template_exists (the EXPECTED_TEMPLATES
// list) — already covered by TestNames_IsTheFullPythonPromptTree — and
// ::test_template_not_empty.
func TestTemplatesAreNotSuspiciouslyShort(t *testing.T) {
	for _, name := range Names() {
		body, err := Load(name)
		if err != nil {
			t.Fatalf("Load(%q): %v", name, err)
		}
		if len(strings.TrimSpace(body)) <= 50 {
			t.Errorf("template %q is suspiciously short (%d trimmed bytes)", name, len(strings.TrimSpace(body)))
		}
	}
}

// Ports TestHuntPromptPlaceholders::test_hunt_prompt_has_required_placeholders.
// The hunter agents substitute each of these; a template that lost one would
// silently ship an un-substituted prompt to the LLM.
func TestHuntTemplatesCarryTheRequiredPlaceholders(t *testing.T) {
	required := []string{
		"{{RESOURCE_GRAPH_SUMMARY}}",
		"{{INVENTORY_STATS}}",
		"{{RELEVANT_EDGES}}",
		"{{REPO_PATH}}",
		"{{DEPTH}}",
	}
	huntTemplates := []string{
		"hunt/iam.txt",
		"hunt/network.txt",
		"hunt/data.txt",
		"hunt/secrets.txt",
		"hunt/compute.txt",
		"hunt/logging.txt",
		"hunt/compliance.txt",
	}
	for _, name := range huntTemplates {
		body, err := Load(name)
		if err != nil {
			t.Fatalf("Load(%q): %v", name, err)
		}
		for _, placeholder := range required {
			if !strings.Contains(body, placeholder) {
				t.Errorf("%s missing placeholder: %s", name, placeholder)
			}
		}
	}
}
