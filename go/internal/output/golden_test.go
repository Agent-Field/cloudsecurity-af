package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// This file is the byte-for-byte parity gate for internal/output.
//
// scripts/gen_golden_output.py builds three CloudSecurityScanResult fixtures in
// Python, writes each one to testdata/<name>.json, re-reads it, and writes the
// five artifacts the Python generators produce from it under testdata/golden/.
// The tests below load the SAME fixture files into the Go structs and diff their
// own output against those bytes.
//
// Regenerate after any change to src/cloudsecurity_af/output/**:
//
//	PYTHONPATH=src ~/.agentfield/packages/cloudsecurity-af/venv/bin/python go/scripts/gen_golden_output.py
//
// The fixtures are, in increasing nastiness:
//
//	scan_result        a fully populated tier-2 scan: four findings (one
//	                   not_exploitable, two sharing a rule id), an attack path,
//	                   drift, remediation, compliance mappings, cost breakdown
//	scan_result_empty  every "nothing to report" branch at once, and a
//	                   whole-second timestamp
//	scan_result_edge   escaping, float spellings, the rule-id fallback, iac_line
//	                   0, an empty iac_file, a non-UTC timestamp and every
//	                   truthiness guard

// goldenFixtures names the fixtures every generator is checked against.
var goldenFixtures = []string{"scan_result", "scan_result_empty", "scan_result_edge"}

// loadFixture reads testdata/<name>.json into the Go model.
func loadFixture(t *testing.T, name string) schemas.CloudSecurityScanResult {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var result schemas.CloudSecurityScanResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return result
}

// readGolden reads testdata/golden/<name> verbatim.
func readGolden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(raw)
}

// assertGolden diffs got against the golden and, on failure, prints the first
// differing line — a 6KB SARIF document is unreadable as a whole-string diff.
func assertGolden(t *testing.T, goldenName, got string) {
	t.Helper()
	want := readGolden(t, goldenName)
	if got == want {
		return
	}
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(want, "\n")
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		var gotLine, wantLine string
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if gotLine == wantLine {
			continue
		}
		t.Fatalf("%s: first difference at line %d\n  go:     %q\n  python: %q\n(go has %d lines, python %d)",
			goldenName, i+1, gotLine, wantLine, len(gotLines), len(wantLines))
	}
	t.Fatalf("%s: documents differ only in trailing bytes (go %d bytes, python %d)",
		goldenName, len(got), len(want))
}

// TestGoldenSarif diffs GenerateSarif against generate_sarif.
func TestGoldenSarif(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			result := loadFixture(t, name)
			assertGolden(t, name+".sarif.json", GenerateSarif(result))
			// render_sarif is generate_sarif under another name.
			assertGolden(t, name+".sarif.json", RenderSarif(result))
		})
	}
}

// TestGoldenGenerateJSON diffs GenerateJSON in both modes against
// generate_json. The pretty mode is CPython's json.dumps spelling; the compact
// mode is pydantic's model_dump_json spelling, which is a different serializer
// entirely (see pydantic.go).
func TestGoldenGenerateJSON(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			result := loadFixture(t, name)
			assertGolden(t, name+".full.json", GenerateJSON(result, true))
			assertGolden(t, name+".full_compact.json", GenerateJSON(result, false))
		})
	}
}

// TestGoldenSummaryJSON diffs GenerateSummaryJSON against
// generate_summary_json.
func TestGoldenSummaryJSON(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			assertGolden(t, name+".summary.json", GenerateSummaryJSON(loadFixture(t, name)))
		})
	}
}

// TestGoldenReport diffs GenerateReport against generate_report.
func TestGoldenReport(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			result := loadFixture(t, name)
			assertGolden(t, name+".report.md", GenerateReport(result))
			assertGolden(t, name+".report.md", RenderReport(result))
		})
	}
}

// TestFixtureRoundTrip proves the Go structs lose nothing the fixture carries:
// re-serialising a loaded fixture with pydantic's own spelling reproduces the
// golden compact dump. If a schemas field were missing or mistyped, every other
// golden here would fail with a confusing diff — this one names it.
func TestFixtureRoundTrip(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			assertGolden(t, name+".full_compact.json", GenerateJSON(loadFixture(t, name), false))
		})
	}
}

// TestRenderJSONParsesTheFullDocument covers render_json, which Python defines
// as json.loads(generate_json(result, pretty=True)).
func TestRenderJSONParsesTheFullDocument(t *testing.T) {
	for _, name := range goldenFixtures {
		t.Run(name, func(t *testing.T) {
			result := loadFixture(t, name)
			got, err := RenderJSON(result)
			if err != nil {
				t.Fatalf("RenderJSON: %v", err)
			}
			var want map[string]any
			if err := json.Unmarshal([]byte(readGolden(t, name+".full.json")), &want); err != nil {
				t.Fatalf("parse golden: %v", err)
			}
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("RenderJSON mismatch\n got %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
}
