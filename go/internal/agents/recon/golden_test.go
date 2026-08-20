package recon

import (
	"os"
	"path/filepath"
	"testing"
)

// The four RECON prompts must be BYTE-IDENTICAL to what the Python agents hand
// to app.harness. The goldens under testdata/golden/ are captured from the real
// Python coroutines by go/scripts/gen_golden.py — they are not transcriptions —
// so a drift in either the template or the substitution logic fails here.
//
// The inputs below MUST stay in sync with the constants at the top of
// gen_golden.py; regenerate the goldens after changing them.

const (
	goldenRepoPath      = "/fixture/repo"
	goldenInventoryPath = "/fixture/work/inventory.json"
	goldenIaCGraphPath  = "/fixture/work/graph.json"
)

// cloudConfigCaseA is CloudConfig().model_dump() — the defaults, with the two
// optional fields explicitly None.
func cloudConfigCaseA() map[string]any {
	return map[string]any{
		"provider":        "aws",
		"regions":         []any{"us-east-1"},
		"account_id":      nil,
		"assume_role_arn": nil,
	}
}

// cloudConfigCaseB has every field populated.
func cloudConfigCaseB() map[string]any {
	return map[string]any{
		"provider":        "gcp",
		"regions":         []any{"us-central1", "europe-west1"},
		"account_id":      "123456789012",
		"assume_role_arn": "arn:aws:iam::123456789012:role/cloudsecurity-scanner",
	}
}

// cloudConfigCaseC is the empty-dict edge case.
func cloudConfigCaseC() map[string]any { return map[string]any{} }

func goldenPrompt(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("reading golden %s (regenerate with go/scripts/gen_golden.py): %v", name, err)
	}
	return string(b)
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	want := goldenPrompt(t, name)
	if got == want {
		return
	}
	// Report the first differing line so the failure is readable for a
	// multi-kilobyte prompt.
	gl, wl := splitLines(got), splitLines(want)
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Fatalf("%s: first difference at line %d\n got: %q\nwant: %q", name, i+1, g, w)
		}
	}
	t.Fatalf("%s: prompts differ but every line matches (trailing-newline drift?): got %d bytes, want %d", name, len(got), len(want))
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func TestBuildIaCReaderPrompt_MatchesPython(t *testing.T) {
	got, err := BuildIaCReaderPrompt(goldenRepoPath)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "iac_reader_prompt.txt", got)
}

func TestBuildResourceGraphBuilderPrompt_MatchesPython(t *testing.T) {
	got, err := BuildResourceGraphBuilderPrompt(goldenInventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "resource_graph_builder_prompt.txt", got)
}

func TestBuildCloudConnectorPrompt_MatchesPython(t *testing.T) {
	cases := map[string]map[string]any{
		"cloud_connector_prompt_a.txt": cloudConfigCaseA(),
		"cloud_connector_prompt_b.txt": cloudConfigCaseB(),
		"cloud_connector_prompt_c.txt": cloudConfigCaseC(),
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := BuildCloudConnectorPrompt(cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertGolden(t, name, got)
		})
	}
}

func TestBuildDriftDetectorPrompt_MatchesPython(t *testing.T) {
	cases := map[string]map[string]any{
		"drift_detector_prompt_a.txt": cloudConfigCaseA(),
		"drift_detector_prompt_b.txt": cloudConfigCaseB(),
		"drift_detector_prompt_c.txt": cloudConfigCaseC(),
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := BuildDriftDetectorPrompt(goldenIaCGraphPath, cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertGolden(t, name, got)
		})
	}
}

// The cloud_config JSON embedded in both prompts must reproduce
// `json.dumps(cloud_config, indent=2)`, whose key order is the pydantic
// CloudConfig declaration order — NOT Go's randomized map order and not
// alphabetical.
func TestCloudConfigJSON_UsesPydanticFieldOrder(t *testing.T) {
	want := "{\n" +
		"  \"provider\": \"aws\",\n" +
		"  \"regions\": [\n    \"us-east-1\"\n  ],\n" +
		"  \"account_id\": null,\n" +
		"  \"assume_role_arn\": null\n" +
		"}"
	for i := 0; i < 20; i++ {
		if got := cloudConfigJSON(cloudConfigCaseA()); got != want {
			t.Fatalf("iteration %d:\n got: %q\nwant: %q", i, got, want)
		}
	}

	if got := cloudConfigJSON(map[string]any{}); got != "{}" {
		t.Errorf("empty config = %q, want %q", got, "{}")
	}
	if got := cloudConfigJSON(nil); got != "null" {
		t.Errorf("nil config = %q, want %q", got, "null")
	}

	// Unknown keys cannot occur for a CloudConfig payload, but they must still
	// be deterministic: known fields first, extras sorted after them.
	got := cloudConfigJSON(map[string]any{"zeta": 1, "provider": "aws", "alpha": 2})
	want = "{\n  \"provider\": \"aws\",\n  \"alpha\": 2,\n  \"zeta\": 1\n}"
	if got != want {
		t.Errorf("extra keys:\n got: %q\nwant: %q", got, want)
	}
}
