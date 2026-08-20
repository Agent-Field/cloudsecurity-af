package hunt

import (
	"context"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// networkHunter ports the four module-level values of
// src/cloudsecurity_af/agents/hunt/network_hunter.py.
//
// Domain keywords, verbatim from the Python call:
//
//	'vpc', 'subnet', 'security_group', 'nacl', 'route', 'peering',
//	'endpoint', 'load_balancer', 'elb', 'alb', 'nlb', 'firewall',
//	'gateway', 'igw', 'nat', 'network_interface', 'eni',
//	'flow_log', 'lb'
var networkHunter = hunter{
	promptPath: "hunt/network.txt",
	keywords: []string{
		"vpc",
		"subnet",
		"security_group",
		"nacl",
		"route",
		"peering",
		"endpoint",
		"load_balancer",
		"elb",
		"alb",
		"nlb",
		"firewall",
		"gateway",
		"igw",
		"nat",
		"network_interface",
		"eni",
		"flow_log",
		"lb",
	},
	agentName: "network_hunter",
	strategy:  "network",
}

// RunNetworkHunter ports run_network_hunter in
// src/cloudsecurity_af/agents/hunt/network_hunter.py.
//
// It is registered as the `run_network_hunter` router reasoner (see
// internal/reasoners) and reached from hunt_phase through app.Call, with the
// same four kwargs: repo_path, resource_graph_path, inventory_path, depth.
//
// See hunter.run in hunt.go for the shared body and its parity notes.
func RunNetworkHunter(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error) {
	return networkHunter.run(ctx, app, repoPath, resourceGraphPath, inventoryPath, depth)
}
