package hunt

import (
	"context"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// loggingHunter ports the four module-level values of
// src/cloudsecurity_af/agents/hunt/logging_hunter.py.
//
// Domain keywords, verbatim from the Python call:
//
//	'cloudtrail', 'flow_log', 'guardduty', 'cloudwatch',
//	'log_group', 'access_log', 'waf_log'
var loggingHunter = hunter{
	promptPath: "hunt/logging.txt",
	keywords: []string{
		"cloudtrail",
		"flow_log",
		"guardduty",
		"cloudwatch",
		"log_group",
		"access_log",
		"waf_log",
	},
	agentName: "logging_hunter",
	strategy:  "logging",
}

// RunLoggingHunter ports run_logging_hunter in
// src/cloudsecurity_af/agents/hunt/logging_hunter.py.
//
// It is registered as the `run_logging_hunter` router reasoner (see
// internal/reasoners) and reached from hunt_phase through app.Call, with the
// same four kwargs: repo_path, resource_graph_path, inventory_path, depth.
//
// See hunter.run in hunt.go for the shared body and its parity notes.
func RunLoggingHunter(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error) {
	return loggingHunter.run(ctx, app, repoPath, resourceGraphPath, inventoryPath, depth)
}
