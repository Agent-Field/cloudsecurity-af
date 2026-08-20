package hunt

import (
	"context"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// dataHunter ports the four module-level values of
// src/cloudsecurity_af/agents/hunt/data_hunter.py.
//
// Domain keywords, verbatim from the Python call:
//
//	's3', 'rds', 'dynamodb', 'ebs', 'efs', 'redshift', 'aurora',
//	'bucket', 'database', 'storage', 'backup', 'snapshot',
//	'encryption', 'db_instance', 'db_option', 'db_parameter',
//	'db_subnet', 'neptune', 'elasticsearch', 'es_domain', 'kms'
var dataHunter = hunter{
	promptPath: "hunt/data.txt",
	keywords: []string{
		"s3",
		"rds",
		"dynamodb",
		"ebs",
		"efs",
		"redshift",
		"aurora",
		"bucket",
		"database",
		"storage",
		"backup",
		"snapshot",
		"encryption",
		"db_instance",
		"db_option",
		"db_parameter",
		"db_subnet",
		"neptune",
		"elasticsearch",
		"es_domain",
		"kms",
	},
	agentName: "data_hunter",
	strategy:  "data",
}

// RunDataHunter ports run_data_hunter in
// src/cloudsecurity_af/agents/hunt/data_hunter.py.
//
// It is registered as the `run_data_hunter` router reasoner (see
// internal/reasoners) and reached from hunt_phase through app.Call, with the
// same four kwargs: repo_path, resource_graph_path, inventory_path, depth.
//
// See hunter.run in hunt.go for the shared body and its parity notes.
func RunDataHunter(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error) {
	return dataHunter.run(ctx, app, repoPath, resourceGraphPath, inventoryPath, depth)
}
