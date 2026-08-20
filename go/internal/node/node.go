// Package node is the cloudsecurity-af wiring layer: it constructs the shared
// *agent.Agent from the environment (the port of src/cloudsecurity_af/app.py's
// module body), registers the exact Python reasoner surface — `scan` and
// `prove` at the top level plus the 20 router reasoners from
// internal/reasoners — and serves it through the SDK.
//
// node.go owns agent construction, registration and Serve. resolve.go owns the
// repo-resolution helpers (_workspaces_root / _resolve_repo). inputs.go owns
// the two top-level reasoner signatures and their control-plane input schemas.
package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/agent"
	"github.com/Agent-Field/agentfield/sdk/go/ai"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/config"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/orch"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/reasoners"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// scanErrorOut is where the pipeline-failure diagnostic goes. Python:
//
//	print(f"SCAN ERROR: {exc}\n{tb}", flush=True)
//
// It is a variable only so tests can capture the bytes; production code must
// never reassign it.
var scanErrorOut io.Writer = os.Stdout

// Node bundles the constructed agent with the resolved environment settings and
// the seams the two top-level reasoner handlers thread through.
type Node struct {
	// App is the SDK agent. It satisfies appx.App (Harness/AI/Note/Call)
	// directly, so it is both the orchestrator's capability seam and the
	// object every router reasoner closes over.
	App *agent.Agent

	// NodeID is the resolved node id (NODE_ID env, or the cloudsecurity default).
	NodeID string
	// AgentFieldServer is the control-plane base URL (AGENTFIELD_SERVER).
	AgentFieldServer string
	// ListenAddress is the ":port" the SDK server binds (":"+PORT).
	ListenAddress string

	// pipelineApp is the capability seam handed to the orchestrator. It
	// defaults to App; tests override it with an appx.Fake.
	pipelineApp appx.App

	// newOrchestrator is `ScanOrchestrator(app=app, input=scan_input)`.
	newOrchestrator func(appx.App, schemas.CloudSecurityInput) (*orch.ScanOrchestrator, error)
	// runOrchestrator is `await orchestrator.run()` — the ONLY statement inside
	// app.py's try/except, and therefore the only source of the 400/500 mapping.
	runOrchestrator func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error)
	// resolveRepo is `_resolve_repo(scan_input.repo_url)`.
	resolveRepo func(context.Context, string) (string, error)

	// registered records every reasoner name passed through the registration
	// path, in order; tags records the tags registered per name (scan/prove ->
	// none; the 20 router reasoners -> the AgentRouter's three domain tags).
	registered []string
	tags       map[string][]string
}

// RegisteredNames returns a copy of the reasoner names registered on this node,
// in registration order — the parity source of truth.
func (n *Node) RegisteredNames() []string {
	return append([]string(nil), n.registered...)
}

// TagsFor returns a copy of the tags registered for name (nil when none).
func (n *Node) TagsFor(name string) []string {
	return append([]string(nil), n.tags[name]...)
}

// BuildAgent constructs the cloudsecurity-af agent from the environment exactly
// as src/cloudsecurity_af/app.py's module body does:
//
//	app = Agent(
//	    node_id=os.getenv("NODE_ID", "cloudsecurity"),
//	    version="0.1.0",
//	    description="AI-Native Cloud Infrastructure Security Scanner",
//	    agentfield_server=os.getenv("AGENTFIELD_SERVER", "http://localhost:8080"),
//	    callback_url=os.getenv("AGENT_CALLBACK_URL", "http://host.docker.internal:8020"),
//	    api_key=os.getenv("AGENTFIELD_API_KEY"),
//	    harness_config=HarnessConfig(provider, model, max_turns, env, opencode_bin, aforge_bin, permission_mode="auto"),
//	    ai_config=AIConfig(provider=..., model=...),
//	)
//
// and `port = int(os.getenv("PORT", "8005"))` from main().
//
// DIVERGENCE 1 — callback URL. Python hardcodes the FALLBACK
// `http://host.docker.internal:8020`, which is (a) a docker-desktop-only host
// name that does not resolve on bare metal or in Linux containers, and (b) the
// wrong port — the node listens on 8005. A bare-metal `python -m
// cloudsecurity_af.app` therefore registers a callback URL the control plane
// cannot reach. Go leaves PublicURL EMPTY when AGENT_CALLBACK_URL is unset, so
// the SDK falls back to `http://localhost:<listen port>` — correct on bare
// metal, and every container deployment (docker-compose, the Go compose add-on,
// `af run`) sets AGENT_CALLBACK_URL explicitly anyway, so the reachable-in-
// docker case is unchanged.
//
// DIVERGENCE 2 — AIConfig. The Go SDK's ai.Config rejects an empty API key at
// construction while Python's AIConfig accepts a missing OPENROUTER_API_KEY. So
// AIConfig is attached ONLY when OPENROUTER_API_KEY is set: construction
// succeeds without a key (matching Python) and the AI call fails at call time
// either way. Python's AIConfig(provider=…, model=…) passes no api_base and
// relies on LiteLLM's routing prefix; Go posts the model verbatim to BaseURL,
// hence the explicit OpenRouter base URL and the prefix strip in aiModelForAPI.
//
// A malformed CLOUDSECURITY_MAX_TURNS returns an error rather than a *Node:
// Python builds AIIntegrationConfig at import time, so the same input makes the
// node fail to boot.
func BuildAgent(defaultNodeID, defaultPort, description string) (*Node, error) {
	cfg, err := buildConfig(defaultNodeID, defaultPort, description)
	if err != nil {
		return nil, err
	}

	app, err := agent.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create agent %q: %w", cfg.NodeID, err)
	}

	n := &Node{
		App:              app,
		NodeID:           cfg.NodeID,
		AgentFieldServer: cfg.AgentFieldURL,
		ListenAddress:    cfg.ListenAddress,
		pipelineApp:      app,
		newOrchestrator:  orch.New,
		runOrchestrator: func(ctx context.Context, o *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
			return o.Run(ctx)
		},
		resolveRepo: resolveRepo,
		tags:        map[string][]string{},
	}
	return n, nil
}

// buildConfig is BuildAgent's pure half: environment -> agent.Config. It is
// split out so the env mapping (which the SDK hides behind an unexported field
// once the Agent is constructed) is directly assertable.
func buildConfig(defaultNodeID, defaultPort, description string) (agent.Config, error) {
	aiConf, err := config.AIConfigFromEnv()
	if err != nil {
		return agent.Config{}, err
	}

	// Python builds HarnessConfig(env=_ai_config.provider_env()) in app.py's
	// module body, so a provider_env() failure (an unwritable XDG_DATA_HOME) is
	// an import-time crash: the node never registers. Propagating the error
	// here keeps the Go node failing at the same point.
	harness, err := harnessConfig(aiConf)
	if err != nil {
		return agent.Config{}, err
	}

	port := envOr("PORT", defaultPort)
	cfg := agent.Config{
		// config.NodeIDOr is the SINGLE NODE_ID resolution rule of the port:
		// internal/phases and internal/orch build every Call target with the
		// same helper, so the id the agent registers under and the prefix of
		// every DAG edge cannot diverge (see config.NodeID's doc comment).
		NodeID:        config.NodeIDOr(defaultNodeID),
		Version:       "0.1.0",
		AgentFieldURL: envOr("AGENTFIELD_SERVER", "http://localhost:8080"),
		Token:         os.Getenv("AGENTFIELD_API_KEY"),
		ListenAddress: ":" + port,
		PublicURL:     os.Getenv("AGENT_CALLBACK_URL"),
		CLIConfig:     &agent.CLIConfig{AppDescription: description},
		HarnessConfig: harness,
	}
	if apiKey := os.Getenv("OPENROUTER_API_KEY"); apiKey != "" {
		cfg.AIConfig = &ai.Config{
			Model:   aiModelForAPI(aiConf.AIModel),
			APIKey:  apiKey,
			BaseURL: "https://openrouter.ai/api/v1",
		}
	}
	return cfg, nil
}

// harnessConfig maps the resolved AI integration configuration onto the SDK
// harness configuration.
//
// Python passes BOTH opencode_bin and aforge_bin to HarnessConfig and lets the
// SDK pick by provider; the Go HarnessConfig has ONE BinPath, so the selection
// happens here. An empty BinPath lets the SDK use the provider's own default
// executable — which is what every other provider (claude-code, codex, gemini)
// gets, exactly as in Python.
func harnessConfig(c config.AIIntegrationConfig) (*agent.HarnessConfig, error) {
	env, err := c.ProviderEnv()
	if err != nil {
		return nil, err
	}
	return &agent.HarnessConfig{
		Provider:       c.Provider,
		Model:          c.HarnessModel,
		MaxTurns:       c.MaxTurns,
		PermissionMode: "auto",
		Env:            env,
		BinPath:        resolvedHarnessBin(c),
	}, nil
}

// resolvedHarnessBin picks the executable for the configured provider.
func resolvedHarnessBin(c config.AIIntegrationConfig) string {
	switch c.Provider {
	case "aforge":
		return c.AforgeBin
	case "opencode":
		return c.OpencodeBin
	default:
		return ""
	}
}

// aiModelForAPI converts the configured AI model into the model ID the
// OpenRouter API expects. Python's .ai() path runs through LiteLLM, which
// CONSUMES a leading "openrouter/" as its routing prefix before calling the
// OpenRouter API; the Go SDK's ai client posts the model string verbatim to
// BaseURL, where "openrouter/minimax/minimax-m2.5" is an invalid model ID.
// Stripping the routing prefix reaches the same model Python does. The HARNESS
// model is untouched (opencode's config expects the prefixed form, and the
// Docker entrypoint derives its model key by stripping the prefix there).
func aiModelForAPI(model string) string {
	return strings.TrimPrefix(model, "openrouter/")
}

// RegisterAll registers the full cloudsecurity-af surface: the two top-level
// reasoners `scan` and `prove` (app.py's @app.reasoner()), then the 20 router
// reasoners mounted through IncludeRouter (app.include_router(reasoner_router)).
//
// Registration ORDER matches app.py: scan and prove are defined before
// include_router runs.
//
// The router carries the AgentRouter's three domain tags. They are SEMANTIC
// tags, not node-identity tags — node identity is node_id=cloudsecurity, so
// callers reach cloudsecurity.scan.
func (n *Node) RegisterAll() {
	// Both top-level reasoners publish the schema the LIVE Python node
	// published for them (reasoners.MustInputSchema reads the captured
	// fixture and panics on a name it does not cover, so this cannot silently
	// fall back to the SDK's contentless default). The 20 router reasoners get
	// theirs the same way, inside reasoners.RegisterAll.
	n.record(reasoners.NameScan, nil)
	n.App.RegisterReasoner(reasoners.NameScan, n.scanHandler,
		agent.WithInputSchema(reasoners.MustInputSchema(reasoners.NameScan)))

	n.record(reasoners.NameProve, nil)
	n.App.RegisterReasoner(reasoners.NameProve, n.proveHandler,
		agent.WithInputSchema(reasoners.MustInputSchema(reasoners.NameProve)))

	router := agent.NewRouter()
	tags := reasoners.Tags()
	for _, name := range reasoners.RegisterAll(router, n.pipelineApp) {
		n.record(name, tags)
	}
	n.App.IncludeRouter(router, agent.RouterOptions{Tags: tags})
}

// record appends name (and its tags) to the node's registration bookkeeping.
// tags==nil records an empty slice so TagsFor("scan") returns no tags.
func (n *Node) record(name string, tags []string) {
	n.registered = append(n.registered, name)
	n.tags[name] = append([]string(nil), tags...)
}

// runPipeline ports app.py::_run_pipeline.
//
// Python:
//
//	orchestrator = ScanOrchestrator(app=app, input=scan_input)
//	repo_path = _resolve_repo(scan_input.repo_url)
//	orchestrator.repo_path = Path(repo_path)
//	orchestrator.checkpoint_dir = orchestrator.repo_path / ".cloudsecurity"
//	try:
//	    result = await orchestrator.run()
//	except ValueError as exc:
//	    raise HTTPException(400, detail={"error": str(exc)})
//	except Exception as exc:
//	    print(f"SCAN ERROR: {exc}\n{traceback.format_exc()}", flush=True)
//	    raise HTTPException(500, detail={"error": f"scan execution failed: {exc}"})
//	return result.model_dump()
//
// The first four statements are OUTSIDE the try, so their exceptions escape
// uncaught and FastAPI renders a generic 500 with the message hidden. Go
// reports them at 500 WITH the message (a documented, deliberate divergence —
// same status, more debuggable) and without the "scan execution failed: "
// prefix, which belongs to the orchestrator branch only.
//
// Note the ordering quirk, reproduced verbatim: the orchestrator is built
// BEFORE the repo is resolved, so ScanConfig.from_input's strict depth parse
// (which raises a ValueError for an unknown depth) fires on the UNCAUGHT path
// and yields a 500, not the 400 a bad `depth` looks like it should get.
//
// Python emits NO note here (unlike sec-af's audit handler) — do not add one.
func (n *Node) runPipeline(ctx context.Context, in schemas.CloudSecurityInput) (any, error) {
	orchestrator, err := n.newOrchestrator(n.pipelineApp, in)
	if err != nil {
		return nil, uncaught(err)
	}

	repoPath, err := n.resolveRepo(ctx, in.RepoURL)
	if err != nil {
		return nil, uncaught(err)
	}
	orchestrator.RepoPath = repoPath
	orchestrator.SetCheckpointDirFromRepoPath()

	result, err := n.runOrchestrator(ctx, orchestrator)
	if err != nil {
		if isValueErrorClass(err) {
			// ValueError-class -> 400 with the RAW message, so the body is
			// byte-identical to Python's str(exc).
			return nil, &agent.ExecuteError{StatusCode: http.StatusBadRequest, Message: err.Error()}
		}
		// DIVERGENCE: Python also prints a full traceback here. Go has no
		// equivalent for an error value, so only the message line is emitted.
		_, _ = fmt.Fprintf(scanErrorOut, "SCAN ERROR: %v\n", err)
		return nil, &agent.ExecuteError{
			StatusCode: http.StatusInternalServerError,
			Message:    "scan execution failed: " + err.Error(),
		}
	}

	// Python: return result.model_dump().
	//
	// afx.Dump, not afx.ToMap: FastAPI serialises the returned dict with
	// json.dumps, which preserves pydantic's field-declaration order
	// (repository, commit_sha, branch, timestamp, …) and spells every float
	// the Python way ("cost_usd": 0.0). A Go map would put the same keys on
	// the wire alphabetically and render 0.0 as 0.
	return afx.Dump(result)
}

// uncaught renders a failure from the statements app.py runs OUTSIDE its
// try/except. See runPipeline for the divergence note.
func uncaught(err error) error {
	return &agent.ExecuteError{StatusCode: http.StatusInternalServerError, Message: err.Error()}
}

// afxBindErrorMarker is the prefix afx.Bind stamps on EVERY validation failure —
// a decode failure ("afx.Bind: unmarshal into ...") and a missing REQUIRED field
// ("afx.Bind: 1 validation error for ResourceInventory: ..."). Every
// `Model.model_validate(...)` in the ported pipeline goes through afx.Bind, so
// this is the text that reaches the 400 body. It is asserted in node_test.go
// against the real afx.Bind; the CLASSIFICATION itself does not use it, see
// isValueErrorClass.
const afxBindErrorMarker = "afx.Bind: "

// isValueErrorClass reports whether err is what Python's `except ValueError`
// in _run_pipeline would catch.
//
// Inside ScanOrchestrator.run() the ONLY ValueError-class exceptions Python can
// raise are pydantic ValidationErrors — every `Model.model_validate(payload)`
// of a phase reply, plus the strict enum coercions inside those models. In the
// Go port those all surface as an *afx.ValidationError. The other failure modes
// are NOT ValueError-class and take the 500 branch, matching Python:
//
//   - _unwrap / _as_dict raise RuntimeError
//   - the missing "verified" key is a KeyError
//   - a control-plane transport failure is an httpx/RuntimeError
//
// The test is errors.As, NOT a substring of the message, and that is
// load-bearing. A bind failure inside a CHILD reasoner is recorded by the
// control plane as that child's error_message and relayed to this process as an
// *agent.ExecuteError whose text still begins "afx.Bind: " — but in Python that
// is an SDK/transport exception in the parent, caught by `except Exception` and
// answered 500 with the "scan execution failed: " prefix. Matching on text
// would answer 400 with the raw child message instead, inverting the
// retryable/client-error class every caller branches on.
func isValueErrorClass(err error) bool {
	var validation *afx.ValidationError
	return errors.As(err, &validation)
}

// Serve registers with the control plane and serves the SDK handler until
// SIGINT/SIGTERM or ctx cancellation.
//
// Unlike pr-af this node adds NO custom HTTP route: app.py grafts a `/health`
// route onto the SDK app, but the Go SDK already serves `/health` itself
// (agent.healthHandler). The two payloads differ — Python's returns
// {"status":"healthy","version":"0.1.0"} and the SDK's returns {"status":"ok"}
// (verified against a booted node) — but every consumer (the Dockerfile
// HEALTHCHECK, the compose healthcheck, the manifest's `healthcheck: /health`)
// only checks for a 2xx, so the SDK route is used as-is rather than shadowed by
// a custom mux.
func (n *Node) Serve(ctx context.Context) error {
	return n.App.Serve(ctx)
}

// envOr returns the value of key, or def when the env var is unset or empty.
//
// Python parity: app.py uses os.getenv(key, default), which substitutes only
// when the key is ABSENT. Treating "" as absent is the deliberate difference —
// an empty PORT/AGENTFIELD_SERVER cannot produce a working node, and
// `af run`/compose export empty strings for unset optional variables.
//
// NODE_ID does NOT go through here: it is resolved by config.NodeIDOr, which
// applies this same rule but is shared with internal/phases and internal/orch
// so the registered id and every Call target cannot be resolved differently.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
