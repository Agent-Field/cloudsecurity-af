package hunt

import (
	"context"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// complianceHunter ports the four module-level values of
// src/cloudsecurity_af/agents/hunt/compliance_hunter.py.
//
// Domain keywords, verbatim from the Python call:
//
//	''
//
// Python parity: that single EMPTY string is dropped by the
// `[keyword.lower() for keyword in domain_keywords if keyword]` filter in
// build_graph_context_for_hunter, leaving no keywords at all — which is the
// code path where _matches() returns True unconditionally. The compliance
// hunter therefore sees EVERY node and EVERY edge in the graph, by design.
var complianceHunter = hunter{
	promptPath: "hunt/compliance.txt",
	keywords:   []string{""},
	agentName:  "compliance_hunter",
	strategy:   "compliance",
}

// RunComplianceHunter ports run_compliance_hunter in
// src/cloudsecurity_af/agents/hunt/compliance_hunter.py.
//
// It is registered as the `run_compliance_hunter` router reasoner (see
// internal/reasoners) and reached from hunt_phase through app.Call, with the
// same four kwargs: repo_path, resource_graph_path, inventory_path, depth.
//
// See hunter.run in hunt.go for the shared body and its parity notes.
func RunComplianceHunter(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error) {
	return complianceHunter.run(ctx, app, repoPath, resourceGraphPath, inventoryPath, depth)
}
