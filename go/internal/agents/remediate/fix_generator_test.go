package remediate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// remediateInputs mirrors go/scripts/gen_golden.py's remediate inputs.json — the
// exact pydantic models the Python builder was driven with, so the golden
// comparison is against the same values rather than a hand transcription.
type remediateInputs struct {
	VerifiedFull schemas.VerifiedFinding `json:"verified_full"`
	VerifiedBare schemas.VerifiedFinding `json:"verified_bare"`
	RepoPath     string                  `json:"repo_path"`
}

func loadInputs(t *testing.T) remediateInputs {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", "inputs.json"))
	if err != nil {
		t.Fatalf("read inputs.json: %v", err)
	}
	var in remediateInputs
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("decode inputs.json: %v", err)
	}
	return in
}

func golden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(raw)
}

// suggestionJSON is a schema-valid RemediationSuggestion the fake harness
// returns. finding_id is deliberately EMPTY: run_fix_generator must not stamp
// one in afterwards.
const suggestionJSON = `{
  "finding_id": "",
  "description": "Scope the trust policy.",
  "diffs": [{"file_path": "main.tf", "original_lines": "a", "patched_lines": "b", "start_line": 12, "end_line": 12}],
  "breaking_change": false,
  "downtime_estimate": "none",
  "effort": "trivial",
  "alternative_approaches": []
}`

// ---------------------------------------------------------------------------
// Prompt golden — the bytes that reach the model
// ---------------------------------------------------------------------------

// TestBuildFixGeneratorPrompt_Golden pins _build_prompt byte-for-byte for a
// fully populated finding (nested attack path, drift, proof and remediation) and
// for one left entirely at its pydantic defaults.
func TestBuildFixGeneratorPrompt_Golden(t *testing.T) {
	in := loadInputs(t)
	cases := []struct {
		name    string
		finding schemas.VerifiedFinding
		want    string
	}{
		{"a_fully_populated", in.VerifiedFull, "fix_prompt_a.txt"},
		{"b_all_defaults", in.VerifiedBare, "fix_prompt_b.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildFixGeneratorPrompt(tc.finding, in.RepoPath)
			if err != nil {
				t.Fatalf("BuildFixGeneratorPrompt: %v", err)
			}
			if want := golden(t, tc.want); got != want {
				t.Errorf("prompt differs from Python\n%s", firstDiff(got, want))
			}
		})
	}
}

// TestBuildFixGeneratorPrompt_RiskScoreIsStrFloat pins `str(finding.risk_score)`:
// Python's str() of a float always shows a decimal point, so a zero score is
// "0.0" and an integral one is "9.0" — never "0" or "9".
func TestBuildFixGeneratorPrompt_RiskScoreIsStrFloat(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0, "- Risk score: 0.0"},
		{9, "- Risk score: 9.0"},
		{7.25, "- Risk score: 7.25"},
		{-1.5, "- Risk score: -1.5"},
	}
	for _, tc := range cases {
		f := schemas.NewVerifiedFinding()
		f.Verdict = schemas.VerdictConfirmed
		f.RiskScore = tc.score
		got, err := BuildFixGeneratorPrompt(f, "/repo")
		if err != nil {
			t.Fatalf("BuildFixGeneratorPrompt: %v", err)
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("risk_score %v did not render as %q", tc.score, tc.want)
		}
	}
}

// TestBuildFixGeneratorPrompt_SubstitutionOrder pins the parity quirk that the
// 12 replacements run in the Python dict's insertion order over one accumulating
// string: a {{REPO_PATH}} embedded in the title is still ahead of the loop and
// gets substituted, while a {{TITLE}} embedded in it is behind it and survives.
func TestBuildFixGeneratorPrompt_SubstitutionOrder(t *testing.T) {
	f := schemas.NewVerifiedFinding()
	f.Verdict = schemas.VerdictLikely
	f.Severity = "low"
	f.Title = "{{TITLE}} at {{REPO_PATH}}"

	got, err := BuildFixGeneratorPrompt(f, "/srv/repo")
	if err != nil {
		t.Fatalf("BuildFixGeneratorPrompt: %v", err)
	}
	if !strings.Contains(got, "- Title: {{TITLE}} at /srv/repo") {
		t.Errorf("expected the later {{REPO_PATH}} to be substituted and the already-consumed {{TITLE}} to survive:\n%s", got)
	}
}

// TestBuildFixGeneratorPrompt_EnumsRenderAsValues pins that {{VERDICT}} and
// {{SEVERITY}} are the enums' `.value`, not their Python repr
// ("Verdict.CONFIRMED") — the Go string types already are the value.
func TestBuildFixGeneratorPrompt_EnumsRenderAsValues(t *testing.T) {
	f := schemas.NewVerifiedFinding()
	f.Verdict = schemas.VerdictNotExploitable
	f.Severity = "critical"

	got, err := BuildFixGeneratorPrompt(f, "/repo")
	if err != nil {
		t.Fatalf("BuildFixGeneratorPrompt: %v", err)
	}
	for _, want := range []string{"- Verdict: not_exploitable", "- Severity: critical"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt is missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// RunFixGenerator
// ---------------------------------------------------------------------------

func okApp() *appx.Fake {
	return &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(suggestionJSON), nil
	})}
}

// TestRunFixGenerator_HarnessOptions pins the tempdir prefix, that project_dir
// is the REPOSITORY (not the tempdir), that exactly one harness call happens,
// and that the tempdir is removed afterwards.
func TestRunFixGenerator_HarnessOptions(t *testing.T) {
	in := loadInputs(t)
	app := okApp()

	got, err := RunFixGenerator(context.Background(), app, "/repo/under/audit", in.VerifiedFull)
	if err != nil {
		t.Fatalf("RunFixGenerator: %v", err)
	}
	if len(app.Harnesses) != 1 {
		t.Fatalf("made %d harness calls, want 1", len(app.Harnesses))
	}
	call := app.Harnesses[0]
	if !strings.Contains(call.Prompt, "You are the CloudSecurity remediation generator.") {
		t.Errorf("prompt does not come from the fix-generator template:\n%s", call.Prompt)
	}
	if base := filepath.Base(call.Opts.Cwd); !strings.HasPrefix(base, fixGeneratorTempPrefix) {
		t.Errorf("cwd = %q, want a tempdir named %q*", call.Opts.Cwd, fixGeneratorTempPrefix)
	}
	if call.Opts.ProjectDir != "/repo/under/audit" {
		t.Errorf("project_dir = %q, want the repo path", call.Opts.ProjectDir)
	}
	if _, err := os.Stat(call.Opts.Cwd); !os.IsNotExist(err) {
		t.Errorf("temp dir %q survived the call (stat err = %v)", call.Opts.Cwd, err)
	}
	if got.Description != "Scope the trust policy." || len(got.Diffs) != 1 || got.Effort != "trivial" {
		t.Errorf("returned %+v, want the model's RemediationSuggestion verbatim", got)
	}
}

// TestRunFixGenerator_DoesNotStampFindingID pins the boundary: `finding_id` is a
// MANDATORY field of the prompt but nothing in the Python agent fills it in
// afterwards, so an empty one must survive the call untouched.
func TestRunFixGenerator_DoesNotStampFindingID(t *testing.T) {
	in := loadInputs(t)
	app := okApp()

	got, err := RunFixGenerator(context.Background(), app, "/repo", in.VerifiedFull)
	if err != nil {
		t.Fatalf("RunFixGenerator: %v", err)
	}
	if got.FindingID != "" {
		t.Errorf("finding_id = %q, want it left exactly as the model returned it", got.FindingID)
	}
}

// TestRunFixGenerator_HarnessErrorUsesTheAgentName pins the agent name that
// reaches extract_harness_result and therefore the error string the phase logs
// before it drops the remediation.
func TestRunFixGenerator_HarnessErrorUsesTheAgentName(t *testing.T) {
	in := loadInputs(t)
	app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return nil, errors.New("boom")
	})}

	_, err := RunFixGenerator(context.Background(), app, "/repo", in.VerifiedBare)
	if want := "FixGenerator harness error: boom"; err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

// TestRunFixGenerator_TempDirIsUniquePerCall guards against a shared work
// directory: remediation_phase runs several fix generators concurrently and
// Python's mkdtemp gives each its own.
func TestRunFixGenerator_TempDirIsUniquePerCall(t *testing.T) {
	in := loadInputs(t)
	app := okApp()

	for i := 0; i < 2; i++ {
		if _, err := RunFixGenerator(context.Background(), app, "/repo", in.VerifiedBare); err != nil {
			t.Fatalf("RunFixGenerator: %v", err)
		}
	}
	if app.Harnesses[0].Opts.Cwd == app.Harnesses[1].Opts.Cwd {
		t.Errorf("both calls shared cwd %q", app.Harnesses[0].Opts.Cwd)
	}
}

// ---------------------------------------------------------------------------
// json.dumps divergences, pinned explicitly rather than hidden
// ---------------------------------------------------------------------------

// TestFindingJSON_DumpModesAreIndistinguishable pins the doc.go claim that
// model_dump(mode="json") — which only this agent asks for — produces the same
// bytes as model_dump() for VerifiedFinding: the golden was generated from the
// json mode, and every field is a scalar, a str-Enum, a list, a nested model or
// None. The assertions below name the field kinds that would break first if a
// future field needed real json-mode coercion.
func TestFindingJSON_DumpModesAreIndistinguishable(t *testing.T) {
	in := loadInputs(t)
	dump := pyfmt.Dumps(in.VerifiedFull, 2)

	for _, want := range []string{
		`"verdict": "confirmed"`,          // str-Enum -> its value
		`"severity": "critical"`,          // str-Enum -> its value
		`"method": "static_analysis"`,     // nested model's str-Enum
		`"risk_score": 9.25`,              // float
		`"iac_line": 12`,                  // int
		`"breaking_change": false`,        // bool
		`"drop_reason": null`,             // Optional[str] = None
		`"scripts_executed": []`,          // default_factory=list
		`"combined_severity": "critical"`, // enum inside the nested AttackPath
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("VerifiedFinding dump is missing %s", want)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) && i < len(w); i++ {
		if g[i] != w[i] {
			return fmt.Sprintf("first difference at line %d:\n  go:     %q\n  python: %q", i+1, g[i], w[i])
		}
	}
	return fmt.Sprintf("line counts differ: go %d lines, python %d lines", len(g), len(w))
}
