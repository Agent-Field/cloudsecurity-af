// Command cloudsecurity-af is the Go CloudSecurity-AF node — the port of
// src/cloudsecurity_af/app.py's main(). It builds the agent from the
// environment, registers the 22-reasoner surface (scan + prove + the 20 router
// reasoners), and serves it until SIGINT/SIGTERM.
//
// Defaults: NODE_ID "cloudsecurity", PORT 8015. Both env vars override;
// docker-compose.go.yml sets NODE_ID=cloudsecurity-go so the Go and Python
// nodes can register against one control plane at the same time.
//
// Boot env (see go/README.md for the full table):
//
//	AGENTFIELD_SERVER          control-plane base URL (default http://localhost:8080)
//	AGENTFIELD_API_KEY         control-plane bearer token
//	AGENT_CALLBACK_URL         base URL the CP uses to reach this node
//	                           (unset -> the SDK's http://localhost:<PORT>)
//	NODE_ID                    node id (default cloudsecurity)
//	PORT                       listen port (default 8015)
//	CLOUDSECURITY_PROVIDER     harness provider (or HARNESS_PROVIDER; default aforge)
//	CLOUDSECURITY_MODEL        harness model (or HARNESS_MODEL)
//	CLOUDSECURITY_AI_MODEL     model for direct .ai() calls (or AI_MODEL)
//	CLOUDSECURITY_MAX_TURNS    harness turn cap (default 50); malformed -> boot failure
//	OPENROUTER_API_KEY         LLM key; AIConfig is attached only when it is set
//	SEC_AF_WORKSPACES_DIR      clone root for remote repo_url values (default /workspaces)
//	CLOUDSECURITY_REPO_PATH    repo path used when repo_url is neither a directory nor a URL
//	AWS_*/GOOGLE_*/AZURE_*     read-only cloud credentials forwarded to the harness
package main

import (
	"context"
	"log"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/node"
)

func main() {
	n, err := node.BuildAgent(
		"cloudsecurity",
		"8015",
		"AI-Native Cloud Infrastructure Security Scanner",
	)
	if err != nil {
		log.Fatalf("cloudsecurity-af: build agent: %v", err)
	}

	n.RegisterAll()

	if err := n.Serve(context.Background()); err != nil {
		log.Fatalf("cloudsecurity-af: serve: %v", err)
	}
}
