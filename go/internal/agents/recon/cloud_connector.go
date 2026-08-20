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

// cloudConnectorPromptPath is PROMPT_PATH in cloud_connector.py.
const cloudConnectorPromptPath = "recon/cloud_connector.txt"

// cloudConnectorAgentName is the `agent_name` local in run_cloud_connector; it
// feeds the tempdir prefix `f"cloudsecurity-{agent_name}-"`.
const cloudConnectorAgentName = "recon-cloud-connector"

// RunCloudConnector ports run_cloud_connector in
// src/cloudsecurity_af/agents/recon/cloud_connector.py.
//
//	prompt = template.replace("{{CLOUD_CONFIG_JSON}}", json.dumps(cloud_config, indent=2))
//	harness_cwd = tempfile.mkdtemp(prefix="cloudsecurity-recon-cloud-connector-")
//	repo_path = harness_cwd
//	try:    result = await app.harness(prompt=prompt, schema=ResourceInventory,
//	                                   cwd=harness_cwd, project_dir=repo_path)
//	        return extract_harness_result(result, ResourceInventory, "Cloud connector")
//	finally: shutil.rmtree(harness_cwd, ignore_errors=True)
//
// Python parity: this agent has NO deterministic fast path — it always calls the
// harness — and unlike the two IaC agents it DOES clean its temp dir up, in a
// `finally`, because nothing downstream reads a file out of it. `project_dir`
// is the temp dir itself, not a repository.
func RunCloudConnector(ctx context.Context, app appx.Harnesser, cloudConfig map[string]any) (schemas.ResourceInventory, error) {
	prompt, err := BuildCloudConnectorPrompt(cloudConfig)
	if err != nil {
		return schemas.ResourceInventory{}, err
	}

	harnessCwd, err := os.MkdirTemp("", "cloudsecurity-"+cloudConnectorAgentName+"-")
	if err != nil {
		return schemas.ResourceInventory{}, fmt.Errorf("cloudsecurity recon: creating cloud-connector work dir: %w", err)
	}
	// Python: `finally: shutil.rmtree(harness_cwd, ignore_errors=True)`.
	defer func() { _ = os.RemoveAll(harnessCwd) }() // ignore_errors=True

	repoPath := harnessCwd
	return harnessx.RunExtract[schemas.ResourceInventory](
		ctx, app, prompt,
		harness.Options{Cwd: harnessCwd, ProjectDir: repoPath},
		"Cloud connector",
	)
}

// BuildCloudConnectorPrompt renders the cloud-connector harness prompt.
// Exported for the golden test.
func BuildCloudConnectorPrompt(cloudConfig map[string]any) (string, error) {
	template, err := prompts.Load(cloudConnectorPromptPath)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(template, "{{CLOUD_CONFIG_JSON}}", cloudConfigJSON(cloudConfig)), nil
}
