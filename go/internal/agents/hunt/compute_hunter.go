package hunt

import (
	"context"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// computeHunter ports the four module-level values of
// src/cloudsecurity_af/agents/hunt/compute_hunter.py.
//
// Domain keywords, verbatim from the Python call:
//
//	'ec2', 'ecs', 'eks', 'lambda', 'fargate', 'instance',
//	'container', 'node_group', 'auto_scaling', 'launch_template',
//	'ecr', 'repository', 'ebs_volume', 'ebs_snapshot',
//	'volume_attachment'
var computeHunter = hunter{
	promptPath: "hunt/compute.txt",
	keywords: []string{
		"ec2",
		"ecs",
		"eks",
		"lambda",
		"fargate",
		"instance",
		"container",
		"node_group",
		"auto_scaling",
		"launch_template",
		"ecr",
		"repository",
		"ebs_volume",
		"ebs_snapshot",
		"volume_attachment",
	},
	agentName: "compute_hunter",
	strategy:  "compute",
}

// RunComputeHunter ports run_compute_hunter in
// src/cloudsecurity_af/agents/hunt/compute_hunter.py.
//
// It is registered as the `run_compute_hunter` router reasoner (see
// internal/reasoners) and reached from hunt_phase through app.Call, with the
// same four kwargs: repo_path, resource_graph_path, inventory_path, depth.
//
// See hunter.run in hunt.go for the shared body and its parity notes.
func RunComputeHunter(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error) {
	return computeHunter.run(ctx, app, repoPath, resourceGraphPath, inventoryPath, depth)
}
