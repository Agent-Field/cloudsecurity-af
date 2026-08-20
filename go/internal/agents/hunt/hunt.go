package hunt

import (
	"context"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/util"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/prompts"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// hunter is the whole of what differs between the seven Python hunter files.
type hunter struct {
	// promptPath is PROMPT_PATH, as a path into the embedded prompt tree.
	// Python: Path(__file__).resolve().parents[2] / "prompts" / "hunt" / "<x>.txt",
	// i.e. src/cloudsecurity_af/prompts/hunt/<x>.txt.
	promptPath string
	// keywords is the domain_keywords list handed to
	// build_graph_context_for_hunter. Order is irrelevant to the result (it is
	// an any() over substring tests) but is kept verbatim for reviewability.
	keywords []string
	// agentName is the string extract_harness_result reports errors under —
	// "iam_hunter", "network_hunter", … — and therefore appears verbatim in
	// the reasoner's error. It is the PYTHON MODULE-ish name, not the strategy.
	agentName string
	// strategy is the single label written into strategies_run.
	strategy string
}

// run is the body every run_*_hunter shares.
//
// Ports (with iam as the example) src/cloudsecurity_af/agents/hunt/iam_hunter.py:
//
//	prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
//	resource_graph_summary, inventory_stats, relevant_edges = build_graph_context_for_hunter(
//	    resource_graph_path, inventory_path, [...])
//	recon_context = f"{resource_graph_summary}\n\n{relevant_edges}\n\nINVENTORY STATS:\n{inventory_stats}"
//	prompt = prompt_template.replace(...)...
//	harness_cwd = str(Path(repo_path).resolve())
//	result = await app.harness(prompt=prompt, schema=HuntResult, cwd=harness_cwd, project_dir=repo_path)
//	parsed = extract_harness_result(result, HuntResult, "iam_hunter")
//	findings = parsed.findings
//	return parsed.model_copy(update={
//	    "total_raw": parsed.total_raw or len(findings),
//	    "deduplicated_count": parsed.deduplicated_count or len(findings),
//	    "strategies_run": ["iam"],
//	})
func (h hunter) run(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error) {
	prompt, err := h.buildPrompt(repoPath, resourceGraphPath, inventoryPath, depth)
	if err != nil {
		// Python parity: PROMPT_PATH.read_text() is inside the coroutine, so a
		// missing template fails THIS reasoner rather than the process. The
		// template is embedded here, so this is unreachable in practice.
		return schemas.HuntResult{}, err
	}

	parsed, err := harnessx.RunExtract[schemas.HuntResult](
		ctx, app, prompt,
		harness.Options{
			// Python parity: cwd is the RESOLVED repo path while project_dir
			// is the path exactly as the caller passed it. The two are only
			// the same string when the caller already resolved it (the
			// orchestrator does; a hand-written .call need not).
			Cwd:        util.ResolvePath(repoPath),
			ProjectDir: repoPath,
		},
		h.agentName,
	)
	if err != nil {
		return schemas.HuntResult{}, err
	}

	// model_copy(update=...) is a SHALLOW copy: findings is the same list
	// object. A Go struct copy shares the same backing array, which matches.
	out := parsed
	findings := parsed.Findings
	// Python `x or y`: 0 is falsy, so only a ZERO count is backfilled. A
	// negative count from a misbehaving model is truthy and survives.
	if out.TotalRaw == 0 {
		out.TotalRaw = len(findings)
	}
	if out.DeduplicatedCount == 0 {
		out.DeduplicatedCount = len(findings)
	}
	out.StrategiesRun = []string{h.strategy}
	return out, nil
}

// buildPrompt renders the harness prompt. Split out from run so the golden test
// can compare it byte-for-byte against the string the Python builder emits.
func (h hunter) buildPrompt(repoPath, resourceGraphPath, inventoryPath, depth string) (string, error) {
	template, err := prompts.Load(h.promptPath)
	if err != nil {
		return "", err
	}

	resourceGraphSummary, inventoryStats, relevantEdges := util.BuildGraphContextForHunter(
		resourceGraphPath, inventoryPath, h.keywords)

	reconContext := resourceGraphSummary + "\n\n" + relevantEdges + "\n\nINVENTORY STATS:\n" + inventoryStats

	// Python parity: the replacements are CHAINED in this exact order, and
	// str.replace has no count limit. Order is observable — a value
	// substituted early is itself scanned by the later replacements, so a
	// resource whose config_summary literally contained "{{RELEVANT_EDGES}}"
	// would have it expanded. Reproduced rather than reordered.
	//
	// Python parity: {{RECON_CONTEXT}} appears in NO hunt template, so the
	// last replacement is a no-op today. It is kept because dropping it would
	// silently change behavior the moment a template gains the placeholder.
	prompt := strings.ReplaceAll(template, "{{REPO_PATH}}", repoPath)
	prompt = strings.ReplaceAll(prompt, "{{DEPTH}}", depth)
	prompt = strings.ReplaceAll(prompt, "{{RESOURCE_GRAPH_SUMMARY}}", resourceGraphSummary)
	prompt = strings.ReplaceAll(prompt, "{{INVENTORY_STATS}}", inventoryStats)
	prompt = strings.ReplaceAll(prompt, "{{RELEVANT_EDGES}}", relevantEdges)
	prompt = strings.ReplaceAll(prompt, "{{RECON_CONTEXT}}", reconContext)
	return prompt, nil
}
