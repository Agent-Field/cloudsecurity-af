package prove

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

// The three constants that are all static_prover.py and live_prover.py differ
// by. Each pair is that module's PROMPT_PATH, its tempfile.mkdtemp prefix and
// the `agent_name` it passes to extract_harness_result.
const (
	staticProverPromptPath = "prove/static_prover.txt"
	staticProverTempPrefix = "cloudsecurity-static-prover-"
	staticProverAgentName  = "StaticProver"
	liveProverPromptPath   = "prove/live_prover.txt"
	liveProverTempPrefix   = "cloudsecurity-live-prover-"
	liveProverAgentName    = "LiveProver"
	// emptyAttackPathJSON is the literal `json.dumps(...) if attack_path else "{}"`
	// fallback for {{ATTACK_PATH_JSON}}.
	emptyAttackPathJSON = "{}"
)

// RunStaticProver ports run_static_prover in
// src/cloudsecurity_af/agents/prove/static_prover.py:
//
//	template = PROMPT_PATH.read_text(encoding="utf-8")
//	prompt = _build_prompt(template, finding, attack_path, tier, repo_path)
//	harness_cwd = tempfile.mkdtemp(prefix="cloudsecurity-static-prover-")
//	try:
//	    result = await app.harness(prompt=prompt, schema=VerifiedFinding,
//	                               cwd=harness_cwd, project_dir=repo_path)
//	    return extract_harness_result(result, VerifiedFinding, "StaticProver")
//	finally:
//	    shutil.rmtree(harness_cwd, ignore_errors=True)
//
// attackPath is Python's `attack_path: AttackPath | None`: nil renders the
// literal "{}" into {{ATTACK_PATH_JSON}} and nothing else changes. See doc.go
// for why it is the LAST parameter here and the second-to-last in Python.
//
// The returned VerifiedFinding is exactly what the model produced — this
// function performs no scoring, no severity flooring and no SARIF rule-id
// synthesis. See doc.go.
func RunStaticProver(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding schemas.RawFinding,
	tier int,
	attackPath *schemas.AttackPath,
) (schemas.VerifiedFinding, error) {
	return runProver(ctx, app, repoPath, finding, tier, attackPath,
		staticProverPromptPath, staticProverTempPrefix, staticProverAgentName)
}

// RunLiveProver ports run_live_prover in
// src/cloudsecurity_af/agents/prove/live_prover.py. It is run_static_prover with
// a different template, tempdir prefix and agent name — see doc.go.
func RunLiveProver(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding schemas.RawFinding,
	tier int,
	attackPath *schemas.AttackPath,
) (schemas.VerifiedFinding, error) {
	return runProver(ctx, app, repoPath, finding, tier, attackPath,
		liveProverPromptPath, liveProverTempPrefix, liveProverAgentName)
}

// runProver is the body both Python modules duplicate verbatim.
func runProver(
	ctx context.Context,
	app appx.Harnesser,
	repoPath string,
	finding schemas.RawFinding,
	tier int,
	attackPath *schemas.AttackPath,
	promptPath string,
	tempPrefix string,
	agentName string,
) (schemas.VerifiedFinding, error) {
	template, err := prompts.Load(promptPath)
	if err != nil {
		// Python parity: PROMPT_PATH.read_text() raising surfaces as a failed
		// reasoner, and it happens BEFORE mkdtemp.
		return schemas.VerifiedFinding{}, err
	}
	prompt := buildProverPrompt(template, finding, attackPath, tier, repoPath)

	harnessCwd, err := os.MkdirTemp("", tempPrefix)
	if err != nil {
		return schemas.VerifiedFinding{}, fmt.Errorf("cloudsecurity prove: creating %s work dir: %w", agentName, err)
	}
	// Python: `finally: shutil.rmtree(harness_cwd, ignore_errors=True)`.
	defer func() { _ = os.RemoveAll(harnessCwd) }() // ignore_errors=True

	return harnessx.RunExtract[schemas.VerifiedFinding](
		ctx, app, prompt,
		// Python parity: cwd is the throwaway tempdir, project_dir is the
		// repository under audit — the prover reads IaC, it does not write it.
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		agentName,
	)
}

// BuildStaticProverPrompt renders the static-prover harness prompt. Exported for
// the golden test, which compares it byte-for-byte against the string
// static_prover._build_prompt emits.
func BuildStaticProverPrompt(
	finding schemas.RawFinding,
	attackPath *schemas.AttackPath,
	tier int,
	repoPath string,
) (string, error) {
	template, err := prompts.Load(staticProverPromptPath)
	if err != nil {
		return "", err
	}
	return buildProverPrompt(template, finding, attackPath, tier, repoPath), nil
}

// BuildLiveProverPrompt renders the live-prover harness prompt. Exported for the
// golden test, which compares it byte-for-byte against the string
// live_prover._build_prompt emits.
func BuildLiveProverPrompt(
	finding schemas.RawFinding,
	attackPath *schemas.AttackPath,
	tier int,
	repoPath string,
) (string, error) {
	template, err := prompts.Load(liveProverPromptPath)
	if err != nil {
		return "", err
	}
	return buildProverPrompt(template, finding, attackPath, tier, repoPath), nil
}

// buildProverPrompt ports the `_build_prompt` that static_prover.py and
// live_prover.py each declare identically:
//
//	replacements = {
//	    "{{TITLE}}": finding.title,
//	    "{{DESCRIPTION}}": finding.description,
//	    "{{CATEGORY}}": finding.category,
//	    "{{HUNTER_STRATEGY}}": finding.hunter_strategy,
//	    "{{IAC_FILE}}": finding.iac_file,
//	    "{{IAC_LINE}}": str(finding.iac_line),
//	    "{{CONFIG_SNIPPET}}": finding.config_snippet,
//	    "{{ESTIMATED_SEVERITY}}": finding.estimated_severity.value,
//	    "{{CONFIDENCE}}": finding.confidence.value,
//	    "{{FINDING_JSON}}": json.dumps(finding.model_dump(), indent=2),
//	    "{{ATTACK_PATH_JSON}}": json.dumps(attack_path.model_dump(), indent=2) if attack_path else "{}",
//	    "{{TIER}}": str(tier),
//	    "{{REPO_PATH}}": repo_path,
//	}
//	for needle, value in replacements.items():
//	    prompt = prompt.replace(needle, value)
//
// PYTHON PARITY — SUBSTITUTION ORDER IS LOAD-BEARING. Python 3.7+ dicts iterate
// in insertion order, so the 13 replacements run in exactly the order written
// above, over the same accumulating string. A value that itself contains a later
// placeholder (a finding titled "{{REPO_PATH}}", a config snippet containing
// "{{TIER}}") really does get substituted a second time. The Go port keeps the
// order rather than doing one pass.
//
// PYTHON PARITY — `if attack_path` is an IDENTITY test in practice: a pydantic
// BaseModel defines neither __bool__ nor __len__, so every AttackPath instance
// is truthy and only None takes the "{}" branch. A nil Go pointer is the same
// condition.
func buildProverPrompt(
	template string,
	finding schemas.RawFinding,
	attackPath *schemas.AttackPath,
	tier int,
	repoPath string,
) string {
	attackPathJSON := emptyAttackPathJSON
	if attackPath != nil {
		attackPathJSON = pyfmt.Dumps(*attackPath, 2)
	}

	// Ordered exactly like the Python dict literal.
	replacements := []struct{ needle, value string }{
		{"{{TITLE}}", finding.Title},
		{"{{DESCRIPTION}}", finding.Description},
		{"{{CATEGORY}}", finding.Category},
		{"{{HUNTER_STRATEGY}}", finding.HunterStrategy},
		{"{{IAC_FILE}}", finding.IaCFile},
		{"{{IAC_LINE}}", strconv.Itoa(finding.IaCLine)},
		{"{{CONFIG_SNIPPET}}", finding.ConfigSnippet},
		{"{{ESTIMATED_SEVERITY}}", finding.EstimatedSeverity.String()},
		{"{{CONFIDENCE}}", finding.Confidence.String()},
		{"{{FINDING_JSON}}", pyfmt.Dumps(finding, 2)},
		{"{{ATTACK_PATH_JSON}}", attackPathJSON},
		{"{{TIER}}", strconv.Itoa(tier)},
		{"{{REPO_PATH}}", repoPath},
	}

	prompt := template
	for _, r := range replacements {
		prompt = strings.ReplaceAll(prompt, r.needle, r.value)
	}
	return prompt
}
