package remediate

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/prompts"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// fixGeneratorPromptPath is PROMPT_PATH in fix_generator.py, resolved against
// the embedded prompt tree instead of the installed package's prompts/
// directory.
const fixGeneratorPromptPath = "remediate/fix_generator.txt"

// fixGeneratorTempPrefix is the tempfile.mkdtemp prefix in run_fix_generator.
const fixGeneratorTempPrefix = "cloudsecurity-fix-generator-"

// fixGeneratorAgentName is the `agent_name` passed to extract_harness_result; it
// appears verbatim in every error message and diagnostic line.
const fixGeneratorAgentName = "FixGenerator"

// RunFixGenerator ports run_fix_generator in
// src/cloudsecurity_af/agents/remediate/fix_generator.py:
//
//	template = PROMPT_PATH.read_text(encoding="utf-8")
//	prompt = _build_prompt(template, finding, repo_path)
//	harness_cwd = tempfile.mkdtemp(prefix="cloudsecurity-fix-generator-")
//	try:
//	    result = await app.harness(prompt=prompt, schema=RemediationSuggestion,
//	                               cwd=harness_cwd, project_dir=repo_path)
//	    return extract_harness_result(result, RemediationSuggestion, "FixGenerator")
//	finally:
//	    shutil.rmtree(harness_cwd, ignore_errors=True)
//
// The returned RemediationSuggestion is exactly what the model produced; this
// function stamps nothing in afterwards, not even finding_id. See doc.go.
func RunFixGenerator(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding schemas.VerifiedFinding,
) (schemas.RemediationSuggestion, error) {
	prompt, err := BuildFixGeneratorPrompt(finding, repoPath)
	if err != nil {
		// Python parity: PROMPT_PATH.read_text() raising surfaces as a failed
		// reasoner, and it happens BEFORE mkdtemp.
		return schemas.RemediationSuggestion{}, err
	}

	harnessCwd, err := os.MkdirTemp("", fixGeneratorTempPrefix)
	if err != nil {
		return schemas.RemediationSuggestion{}, fmt.Errorf("cloudsecurity remediate: creating fix-generator work dir: %w", err)
	}
	// Python: `finally: shutil.rmtree(harness_cwd, ignore_errors=True)`.
	defer func() { _ = os.RemoveAll(harnessCwd) }() // ignore_errors=True

	return harnessx.RunExtract[schemas.RemediationSuggestion](
		ctx, app, prompt,
		// Python parity: cwd is the throwaway tempdir, project_dir is the
		// repository whose IaC the patch targets.
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		fixGeneratorAgentName,
	)
}

// BuildFixGeneratorPrompt ports _build_prompt. Exported for the golden test,
// which compares it byte-for-byte against the string the Python builder emits.
//
//	replacements = {
//	    "{{TITLE}}": finding.title,
//	    "{{DESCRIPTION}}": finding.description,
//	    "{{VERDICT}}": finding.verdict.value,
//	    "{{SEVERITY}}": finding.severity.value,
//	    "{{CATEGORY}}": finding.category,
//	    "{{IAC_FILE}}": finding.iac_file,
//	    "{{IAC_LINE}}": str(finding.iac_line),
//	    "{{CONFIG_SNIPPET}}": finding.config_snippet,
//	    "{{SARIF_RULE_ID}}": finding.sarif_rule_id,
//	    "{{RISK_SCORE}}": str(finding.risk_score),
//	    "{{FINDING_JSON}}": json.dumps(finding.model_dump(mode="json"), indent=2),
//	    "{{REPO_PATH}}": repo_path,
//	}
//	for needle, value in replacements.items():
//	    prompt = prompt.replace(needle, value)
//
// PYTHON PARITY — SUBSTITUTION ORDER IS LOAD-BEARING. Python 3.7+ dicts iterate
// in insertion order, so the 12 replacements run in exactly the order written
// above over the same accumulating string, and a value containing a later
// placeholder is substituted a second time. The Go port keeps the order.
//
// PYTHON PARITY — {{RISK_SCORE}} IS `str(float)`, not a rounded or formatted
// number: 0.0 renders as "0.0", 8.5 as "8.5", 7.25 as "7.25". pyfmt.FormatFloat
// is repr(float), which is what str(float) has been since Python 3.1.
func BuildFixGeneratorPrompt(finding schemas.VerifiedFinding, repoPath string) (string, error) {
	template, err := prompts.Load(fixGeneratorPromptPath)
	if err != nil {
		return "", err
	}

	// Ordered exactly like the Python dict literal.
	replacements := []struct{ needle, value string }{
		{"{{TITLE}}", finding.Title},
		{"{{DESCRIPTION}}", finding.Description},
		{"{{VERDICT}}", finding.Verdict.String()},
		{"{{SEVERITY}}", finding.Severity.String()},
		{"{{CATEGORY}}", finding.Category},
		{"{{IAC_FILE}}", finding.IaCFile},
		{"{{IAC_LINE}}", strconv.Itoa(finding.IaCLine)},
		{"{{CONFIG_SNIPPET}}", finding.ConfigSnippet},
		{"{{SARIF_RULE_ID}}", finding.SARIFRuleID},
		{"{{RISK_SCORE}}", pyfmt.FormatFloat(finding.RiskScore)},
		{"{{FINDING_JSON}}", pyfmt.Dumps(finding, 2)},
		{"{{REPO_PATH}}", repoPath},
	}

	prompt := template
	for _, r := range replacements {
		prompt = strings.ReplaceAll(prompt, r.needle, r.value)
	}
	return prompt, nil
}
