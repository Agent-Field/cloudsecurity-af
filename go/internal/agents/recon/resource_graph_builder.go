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

// graphBuilderPromptPath is PROMPT_PATH in resource_graph_builder.py.
const graphBuilderPromptPath = "recon/resource_graph_builder.txt"

// graphBuilderTempPrefix is the tempfile.mkdtemp prefix in
// run_resource_graph_builder.
const graphBuilderTempPrefix = "cloudsecurity-recon-graph-builder-"

// RunResourceGraphBuilder ports run_resource_graph_builder in
// src/cloudsecurity_af/agents/recon/resource_graph_builder.py:
//
//	work_dir = tempfile.mkdtemp(prefix="cloudsecurity-recon-graph-builder-")
//	try:
//	    return _fast_build(inventory_path, work_dir)
//	except Exception as exc:
//	    log.warning("Deterministic graph builder failed (%s), falling back to harness", exc)
//	    return await _harness_fallback(app, repo_path, inventory_path, work_dir)
//
// PYTHON PARITY: as in iac_reader.py the work directory is deliberately NOT
// removed — the returned ResourceGraph.graph_saved_path points into it and the
// HUNT phase reads that file for every hunter's graph context.
//
// Python parity: repo_path is accepted and used ONLY as the harness project_dir
// on the fallback path; the deterministic build ignores it.
func RunResourceGraphBuilder(ctx context.Context, app appx.Harnesser, repoPath, inventoryPath string) (schemas.ResourceGraph, error) {
	workDir, err := os.MkdirTemp("", graphBuilderTempPrefix)
	if err != nil {
		return schemas.ResourceGraph{}, fmt.Errorf("cloudsecurity recon: creating graph-builder work dir: %w", err)
	}

	graph, fastErr := graphFastBuild(inventoryPath, workDir)
	if fastErr == nil {
		return graph, nil
	}
	logWarning("cloudsecurity_af.agents.recon.resource_graph_builder",
		"Deterministic graph builder failed (%v), falling back to harness", fastErr)
	return graphHarnessFallback(ctx, app, repoPath, inventoryPath, workDir)
}

// graphFastBuild ports _fast_build.
func graphFastBuild(inventoryPath, workDir string) (schemas.ResourceGraph, error) {
	graphPath, totalNodes, totalEdges, err := BuildGraphFromInventory(inventoryPath, workDir)
	if err != nil {
		return schemas.ResourceGraph{}, err
	}
	return schemas.ResourceGraph{
		GraphSavedPath: graphPath,
		TotalNodes:     totalNodes,
		TotalEdges:     totalEdges,
	}, nil
}

// graphHarnessFallback ports _harness_fallback.
func graphHarnessFallback(ctx context.Context, app appx.Harnesser, repoPath, inventoryPath, workDir string) (schemas.ResourceGraph, error) {
	prompt, err := BuildResourceGraphBuilderPrompt(inventoryPath)
	if err != nil {
		return schemas.ResourceGraph{}, err
	}
	return harnessx.RunExtract[schemas.ResourceGraph](
		ctx, app, prompt,
		harness.Options{Cwd: workDir, ProjectDir: repoPath},
		"Resource graph builder",
	)
}

// BuildResourceGraphBuilderPrompt renders the resource-graph-builder harness
// prompt. Exported for the golden test.
func BuildResourceGraphBuilderPrompt(inventoryPath string) (string, error) {
	template, err := prompts.Load(graphBuilderPromptPath)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(template, "{{INVENTORY_PATH}}", inventoryPath), nil
}
