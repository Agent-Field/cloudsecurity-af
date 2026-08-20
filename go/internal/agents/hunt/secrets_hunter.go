package hunt

import (
	"context"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// secretsHunter ports the four module-level values of
// src/cloudsecurity_af/agents/hunt/secrets_hunter.py.
//
// Domain keywords, verbatim from the Python call:
//
//	'secret', 'kms', 'ssm', 'parameter_store', 'credential', 'key',
//	'certificate', 'access_key', 'password', 'lambda', 'instance',
//	'db_instance', 'provider'
var secretsHunter = hunter{
	promptPath: "hunt/secrets.txt",
	keywords: []string{
		"secret",
		"kms",
		"ssm",
		"parameter_store",
		"credential",
		"key",
		"certificate",
		"access_key",
		"password",
		"lambda",
		"instance",
		"db_instance",
		"provider",
	},
	agentName: "secrets_hunter",
	strategy:  "secrets",
}

// RunSecretsHunter ports run_secrets_hunter in
// src/cloudsecurity_af/agents/hunt/secrets_hunter.py.
//
// It is registered as the `run_secrets_hunter` router reasoner (see
// internal/reasoners) and reached from hunt_phase through app.Call, with the
// same four kwargs: repo_path, resource_graph_path, inventory_path, depth.
//
// See hunter.run in hunt.go for the shared body and its parity notes.
func RunSecretsHunter(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error) {
	return secretsHunter.run(ctx, app, repoPath, resourceGraphPath, inventoryPath, depth)
}
