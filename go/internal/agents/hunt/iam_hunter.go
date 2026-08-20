package hunt

import (
	"context"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// iamHunter ports the four module-level values of
// src/cloudsecurity_af/agents/hunt/iam_hunter.py.
//
// Domain keywords, verbatim from the Python call:
//
//	'iam', 'role', 'policy', 'user', 'group', 'assume_role',
//	'trust', 'permission', 'mfa'
var iamHunter = hunter{
	promptPath: "hunt/iam.txt",
	keywords: []string{
		"iam",
		"role",
		"policy",
		"user",
		"group",
		"assume_role",
		"trust",
		"permission",
		"mfa",
	},
	agentName: "iam_hunter",
	strategy:  "iam",
}

// RunIAMHunter ports run_iam_hunter in
// src/cloudsecurity_af/agents/hunt/iam_hunter.py.
//
// It is registered as the `run_iam_hunter` router reasoner (see
// internal/reasoners) and reached from hunt_phase through app.Call, with the
// same four kwargs: repo_path, resource_graph_path, inventory_path, depth.
//
// See hunter.run in hunt.go for the shared body and its parity notes.
func RunIAMHunter(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error) {
	return iamHunter.run(ctx, app, repoPath, resourceGraphPath, inventoryPath, depth)
}
