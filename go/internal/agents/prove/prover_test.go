package prove

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

// proveInputs mirrors go/scripts/gen_golden.py's prove inputs.json — the exact
// pydantic models the Python builders were driven with, so the golden
// comparison is against the same values rather than a hand transcription.
type proveInputs struct {
	FindingFull schemas.RawFinding `json:"finding_full"`
	FindingBare schemas.RawFinding `json:"finding_bare"`
	AttackPath  schemas.AttackPath `json:"attack_path"`
	RepoPath    string             `json:"repo_path"`
}

func loadInputs(t *testing.T) proveInputs {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", "inputs.json"))
	if err != nil {
		t.Fatalf("read inputs.json: %v", err)
	}
	var in proveInputs
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

// verifiedJSON is a schema-valid VerifiedFinding the fake harness can return.
// It deliberately leaves sarif_rule_id EMPTY: the prover must not fill it in.
const verifiedJSON = `{
  "id": "v-1",
  "title": "verified",
  "verdict": "confirmed",
  "severity": "high",
  "category": "overprivilege",
  "risk_score": 7.5,
  "hunter_strategy": "iam"
}`

// ---------------------------------------------------------------------------
// Prompt goldens — the bytes that reach the model
// ---------------------------------------------------------------------------

// TestBuildProverPrompts_Golden pins both `_build_prompt` implementations
// byte-for-byte, with and without an attack path.
func TestBuildProverPrompts_Golden(t *testing.T) {
	in := loadInputs(t)
	path := in.AttackPath

	cases := []struct {
		name    string
		build   func(schemas.RawFinding, *schemas.AttackPath, int, string) (string, error)
		finding schemas.RawFinding
		path    *schemas.AttackPath
		tier    int
		want    string
	}{
		{"static_with_attack_path", BuildStaticProverPrompt, in.FindingFull, &path, 1, "static_prompt_a.txt"},
		{"static_without_attack_path", BuildStaticProverPrompt, in.FindingBare, nil, 2, "static_prompt_b.txt"},
		{"live_with_attack_path", BuildLiveProverPrompt, in.FindingFull, &path, 2, "live_prompt_a.txt"},
		{"live_without_attack_path", BuildLiveProverPrompt, in.FindingBare, nil, 3, "live_prompt_b.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.build(tc.finding, tc.path, tc.tier, in.RepoPath)
			if err != nil {
				t.Fatalf("build prompt: %v", err)
			}
			if want := golden(t, tc.want); got != want {
				t.Errorf("prompt differs from Python\n%s", firstDiff(got, want))
			}
		})
	}
}

// TestBuildProverPrompt_NilAttackPathRendersEmptyObject pins the `if attack_path
// else "{}"` branch: no attack path becomes the two-character literal, not
// `null` and not an empty AttackPath dump.
func TestBuildProverPrompt_NilAttackPathRendersEmptyObject(t *testing.T) {
	in := loadInputs(t)
	got, err := BuildStaticProverPrompt(in.FindingBare, nil, 1, in.RepoPath)
	if err != nil {
		t.Fatalf("BuildStaticProverPrompt: %v", err)
	}
	if !strings.Contains(got, "- Attack path context:\n{}\n") {
		t.Errorf("attack-path block is not the literal {}:\n%s", got)
	}
}

// TestBuildProverPrompt_SubstitutionOrder pins the parity quirk that the 13
// replacements run in the Python dict's insertion order over one accumulating
// string, so a placeholder embedded in an EARLIER value is substituted by a
// LATER replacement and vice-versa.
func TestBuildProverPrompt_SubstitutionOrder(t *testing.T) {
	f := schemas.NewRawFinding()
	// {{TITLE}} is replaced FIRST, so a {{TIER}} embedded in the title is still
	// ahead of the loop and gets substituted, while a {{TITLE}} embedded in it
	// is already behind the loop and survives verbatim.
	f.Title = "{{TITLE}} tier={{TIER}}"
	f.Category = "cat"
	f.HunterStrategy = "iam"

	got, err := BuildStaticProverPrompt(f, nil, 7, "/repo")
	if err != nil {
		t.Fatalf("BuildStaticProverPrompt: %v", err)
	}
	if !strings.Contains(got, "- Finding title: {{TITLE}} tier=7") {
		t.Errorf("expected the later {{TIER}} to be substituted and the already-consumed {{TITLE}} to survive:\n%s", got)
	}
}

// TestBuildProverPrompt_ZeroFloatsRenderPythonStyle pins the single most likely
// byte drift: Go's encoding/json writes a zero float as "0", Python as "0.0".
func TestBuildProverPrompt_ZeroFloatsRenderPythonStyle(t *testing.T) {
	f := schemas.NewRawFinding()
	path := schemas.NewAttackPath()
	path.ID = "p"

	got, err := BuildStaticProverPrompt(f, &path, 1, "/repo")
	if err != nil {
		t.Fatalf("BuildStaticProverPrompt: %v", err)
	}
	// AttackPath.blast_radius.estimated_data_volume is Optional -> null, and the
	// finding's benchmark_id is Optional -> null; both must be present, not
	// omitted.
	for _, want := range []string{`"benchmark_id": null`, `"estimated_data_volume": null`, `"resources": []`} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt is missing %s (pydantic model_dump emits every field)", want)
		}
	}
}

// ---------------------------------------------------------------------------
// RunStaticProver / RunLiveProver
// ---------------------------------------------------------------------------

func okApp() *appx.Fake {
	return &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(verifiedJSON), nil
	})}
}

// TestRunProver_HarnessOptions pins, for both provers, the tempdir prefix, that
// project_dir is the REPOSITORY (not the tempdir), that exactly one harness call
// happens, and that the tempdir is removed afterwards.
func TestRunProver_HarnessOptions(t *testing.T) {
	in := loadInputs(t)
	path := in.AttackPath

	cases := []struct {
		name       string
		run        func(context.Context, appx.Harnesser, string, schemas.RawFinding, int, *schemas.AttackPath) (schemas.VerifiedFinding, error)
		wantPrefix string
		wantPrompt string
	}{
		{"static", RunStaticProver, staticProverTempPrefix, "You are the CloudSecurity static prover."},
		{"live", RunLiveProver, liveProverTempPrefix, "You are the CloudSecurity live prover."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := okApp()
			got, err := tc.run(context.Background(), app, "/repo/under/audit", in.FindingFull, 2, &path)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if len(app.Harnesses) != 1 {
				t.Fatalf("made %d harness calls, want 1", len(app.Harnesses))
			}
			call := app.Harnesses[0]
			if !strings.Contains(call.Prompt, tc.wantPrompt) {
				t.Errorf("prompt does not come from the %s template:\n%s", tc.name, call.Prompt)
			}
			if base := filepath.Base(call.Opts.Cwd); !strings.HasPrefix(base, tc.wantPrefix) {
				t.Errorf("cwd = %q, want a tempdir named %q*", call.Opts.Cwd, tc.wantPrefix)
			}
			if call.Opts.ProjectDir != "/repo/under/audit" {
				t.Errorf("project_dir = %q, want the repo path", call.Opts.ProjectDir)
			}
			if _, err := os.Stat(call.Opts.Cwd); !os.IsNotExist(err) {
				t.Errorf("temp dir %q survived the call (stat err = %v)", call.Opts.Cwd, err)
			}
			if got.ID != "v-1" || got.Verdict != schemas.VerdictConfirmed || got.RiskScore != 7.5 {
				t.Errorf("returned %+v, want the model's VerifiedFinding verbatim", got)
			}
		})
	}
}

// TestRunProver_DoesNotSynthesizeSARIFRuleID pins the boundary between this
// package and phases.py / output/sarif.py: a prover returns the model's finding
// UNCHANGED, so an empty sarif_rule_id stays empty here. The
// `cloudsecurity/<strategy>/<category>` formula lives in the two fallbacks, not
// in the prover.
func TestRunProver_DoesNotSynthesizeSARIFRuleID(t *testing.T) {
	in := loadInputs(t)
	app := okApp()

	got, err := RunStaticProver(context.Background(), app, "/repo", in.FindingFull, 1, nil)
	if err != nil {
		t.Fatalf("RunStaticProver: %v", err)
	}
	if got.SARIFRuleID != "" {
		t.Errorf("sarif_rule_id = %q, want it left exactly as the model returned it", got.SARIFRuleID)
	}
	if got.SARIFSecuritySeverity != 0 {
		t.Errorf("sarif_security_severity = %v, want the model's value", got.SARIFSecuritySeverity)
	}
}

// TestRunProver_HarnessErrorUsesTheAgentName pins the two agent names that reach
// extract_harness_result and therefore the error strings the phase logs.
func TestRunProver_HarnessErrorUsesTheAgentName(t *testing.T) {
	in := loadInputs(t)
	cases := []struct {
		name string
		run  func(context.Context, appx.Harnesser, string, schemas.RawFinding, int, *schemas.AttackPath) (schemas.VerifiedFinding, error)
		want string
	}{
		{"static", RunStaticProver, "StaticProver harness error: boom"},
		{"live", RunLiveProver, "LiveProver harness error: boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
				return nil, errors.New("boom")
			})}
			_, err := tc.run(context.Background(), app, "/repo", in.FindingBare, 1, nil)
			if err == nil || err.Error() != tc.want {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestRunProver_TempDirIsUniquePerCall guards against a shared work directory:
// prove_phase runs up to three provers concurrently, and Python's mkdtemp gives
// each its own.
func TestRunProver_TempDirIsUniquePerCall(t *testing.T) {
	in := loadInputs(t)
	app := okApp()

	for i := 0; i < 2; i++ {
		if _, err := RunStaticProver(context.Background(), app, "/repo", in.FindingBare, 1, nil); err != nil {
			t.Fatalf("RunStaticProver: %v", err)
		}
	}
	if app.Harnesses[0].Opts.Cwd == app.Harnesses[1].Opts.Cwd {
		t.Errorf("both calls shared cwd %q", app.Harnesses[0].Opts.Cwd)
	}
}

// ---------------------------------------------------------------------------
// pyjson divergences, pinned explicitly rather than hidden
// ---------------------------------------------------------------------------

// TestPyDumps_DocumentedDivergences pins the two places where the Go dump cannot
// match Python, so a reader sees the exact shape of the gap instead of
// discovering it in production. Both are documented in doc.go and pyjson.go.
func TestPyDumps_DocumentedDivergences(t *testing.T) {
	t.Run("int_leaf_becomes_a_float", func(t *testing.T) {
		// afx.Bind decodes a JSON `1` into an `any` field as float64(1), which
		// renders as Python's float repr. Python's json decoder keeps the int.
		diff := schemas.ConfigDiff{Attribute: "a", IaCValue: float64(1)}
		if got := pyfmt.Dumps(diff, 0); !strings.Contains(got, `"iac_value": 1.0`) {
			t.Errorf("got %s, want the documented 1.0 rendering", got)
		}
		// A json.Number leaf — what a UseNumber decoder produces — IS exact.
		diff.IaCValue = json.Number("1")
		if got := pyfmt.Dumps(diff, 0); !strings.Contains(got, `"iac_value": 1`) {
			t.Errorf("got %s, want a json.Number to keep its int literal", got)
		}
	})

	t.Run("map_keys_are_sorted", func(t *testing.T) {
		d := schemas.DriftedResource{IaCConfig: map[string]any{"z": 1.0, "a": 2.0}}
		got := pyfmt.Dumps(d, 0)
		if !strings.Contains(got, `"iac_config": {"a": 2.0, "z": 1.0}`) {
			t.Errorf("got %s, want Go map keys sorted (Python would keep insertion order)", got)
		}
	})
}

// TestBuildProverPrompt_NilSliceRendersNull pins the one latent gap between
// pyfmt.Dumps and pydantic: a NIL Go slice renders as `null` where a
// default_factory=list field always dumps as `[]`. It is unreachable in the live
// DAG (a finding always arrives via afx.Bind, whose UnmarshalJSON seeds `[]`),
// and the test exists so that a future in-process caller sees the behavior
// documented rather than discovering it in a prompt.
func TestBuildProverPrompt_NilSliceRendersNull(t *testing.T) {
	seeded := schemas.NewRawFinding() // what afx.Bind produces
	got, err := BuildStaticProverPrompt(seeded, nil, 1, "/repo")
	if err != nil {
		t.Fatalf("BuildStaticProverPrompt: %v", err)
	}
	if !strings.Contains(got, `"resources": []`) {
		t.Errorf("a seeded RawFinding must dump resources as [], got:\n%s", got)
	}

	bare := schemas.RawFinding{} // a hand-built struct literal: nil slice
	got, err = BuildStaticProverPrompt(bare, nil, 1, "/repo")
	if err != nil {
		t.Fatalf("BuildStaticProverPrompt: %v", err)
	}
	if !strings.Contains(got, `"resources": null`) {
		t.Errorf("expected the documented nil-slice rendering, got:\n%s", got)
	}
}

// TestPyDumps_EscapesLikePython pins ensure_ascii=True and the absence of Go's
// HTML escaping — the difference is visible in almost every real finding title.
func TestPyDumps_EscapesLikePython(t *testing.T) {
	f := schemas.NewRawFinding()
	f.Title = `<a> & "b" — ünï 😀`
	got := pyfmt.Dumps(f, 0)
	want := `"title": "<a> & \"b\" \u2014 \u00fcn\u00ef \ud83d\ude00"`
	if !strings.Contains(got, want) {
		t.Errorf("got %s\nwant it to contain %s", got, want)
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
