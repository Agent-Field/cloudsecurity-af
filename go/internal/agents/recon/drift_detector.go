package recon

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/prompts"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// driftDetectorPromptPath is PROMPT_PATH in drift_detector.py.
const driftDetectorPromptPath = "recon/drift_detector.txt"

// driftDetectorAgentName is the `agent_name` local in run_drift_detector.
const driftDetectorAgentName = "recon-drift-detector"

// RunDriftDetector ports run_drift_detector in
// src/cloudsecurity_af/agents/recon/drift_detector.py.
//
//	prompt = template.replace("{{IAC_GRAPH_PATH}}", iac_graph_path).replace(
//	    "{{CLOUD_CONFIG_JSON}}", json.dumps(cloud_config, indent=2))
//	harness_cwd = tempfile.mkdtemp(prefix="cloudsecurity-recon-drift-detector-")
//	repo_path = harness_cwd
//	try:    result = await app.harness(prompt=prompt, schema=DriftReport,
//	                                   cwd=harness_cwd, project_dir=repo_path)
//	        return extract_harness_result(result, DriftReport, "Drift detector")
//	finally: shutil.rmtree(harness_cwd, ignore_errors=True)
func RunDriftDetector(ctx context.Context, app appx.Harnesser, iacGraphPath string, cloudConfig map[string]any) (schemas.DriftReport, error) {
	prompt, err := BuildDriftDetectorPrompt(iacGraphPath, cloudConfig)
	if err != nil {
		return schemas.DriftReport{}, err
	}

	harnessCwd, err := os.MkdirTemp("", "cloudsecurity-"+driftDetectorAgentName+"-")
	if err != nil {
		return schemas.DriftReport{}, fmt.Errorf("cloudsecurity recon: creating drift-detector work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(harnessCwd) }() // ignore_errors=True

	repoPath := harnessCwd
	return harnessx.RunExtract[schemas.DriftReport](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		"Drift detector",
	)
}

// BuildDriftDetectorPrompt renders the drift-detector harness prompt. Exported
// for the golden test.
//
// PYTHON PARITY BUG, REPRODUCED VERBATIM: the Python substitutes
// `{{IAC_GRAPH_PATH}}`, but prompts/recon/drift_detector.txt contains
// `{{IAC_GRAPH_JSON}}`. The replacement is therefore a NO-OP: the graph path is
// never interpolated and the literal token `{{IAC_GRAPH_JSON}}` is what reaches
// the model, which is why the prompt tells it to "Parse IaC graph nodes/edges"
// with no graph in sight. The Go port performs the same no-op replacement so the
// prompt bytes match; fixing it would change what the LLM sees and is a Python-
// side change, not a port change.
func BuildDriftDetectorPrompt(iacGraphPath string, cloudConfig map[string]any) (string, error) {
	template, err := prompts.Load(driftDetectorPromptPath)
	if err != nil {
		return "", err
	}
	prompt := strings.ReplaceAll(template, "{{IAC_GRAPH_PATH}}", iacGraphPath)
	prompt = strings.ReplaceAll(prompt, "{{CLOUD_CONFIG_JSON}}", cloudConfigJSON(cloudConfig))
	return prompt, nil
}
