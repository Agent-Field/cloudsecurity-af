// Package reasoners ports src/cloudsecurity_af/reasoners/ — the AgentRouter and
// the 20 `@router.reasoner()` functions it carries (recon.py, hunt.py, chain.py,
// prove.py, remediate.py, phases.py).
//
// Every Python reasoner in that tree is a THIN adapter: it binds its dict
// arguments into pydantic models, calls one function in
// cloudsecurity_af.agents.* (or one phase body in phases.py), and returns
// `result.model_dump()`. This package is the same thin layer over
// internal/agents/* and internal/phases, so the control-plane surface and the
// business logic stay in separate packages exactly as they are in Python.
//
// RETURN SHAPE: every handler returns an afx.Payload, the Go stand-in for that
// model_dump() dict. It keeps pydantic's FIELD-DECLARATION order (which
// json.dumps preserves and a Go map does not) and renders floats the Python way
// (`"risk_score": 0.0`, not `0`). See internal/afx/payload.go.
//
// NOTES: none of the 20 router reasoners emits an app.note()/router.note() —
// verified by grep over src/cloudsecurity_af/reasoners/. Neither do the phase
// bodies. The only note-shaped signal in the Python node is
// ScanOrchestrator._emit_progress, which builds a ScanProgress and then does
// NOT emit it (see internal/orch). So no Go handler here calls App.Note either.
//
// ERRORS: Python lets every exception escape the reasoner (there is no
// try/except in reasoners/*.py outside hunt_phase's per-hunter guard and
// prove/remediation_phase's per-item guards, all of which live in
// internal/phases). A Go handler therefore returns its error unchanged and lets
// the SDK render it as a failed execution — which is precisely what the strict
// afx.UnwrapStrict on the calling side turns back into an error.
package reasoners

import (
	"context"
	"errors"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/chain"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/hunt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/prove"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/recon"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/remediate"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/phases"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// RegisterAll registers the 20 router reasoners on r in the order
// reasoners/__init__.py imports them (see routerNames), and returns that
// ordered name list so the caller can record the surface it just mounted.
//
// app is the single capability seam every handler closes over — Python's
// `_runtime_router`, the AgentRouter that proxies .harness()/.call() to the
// Agent. The harness-driven agent reasoners need only appx.Harnesser and the
// five phase reasoners need only appx.Caller; taking the full appx.App here
// keeps ONE parameter for the caller (node.BuildAgent passes the live
// *agent.Agent) while each handler still narrows to what it uses.
//
// Tags are NOT applied per reasoner: Python attaches them to the AgentRouter
// itself, and the Go SDK's equivalent is agent.RouterOptions{Tags: ...} at the
// IncludeRouter call site. Use reasoners.Tags() there.
func RegisterAll(r *agent.Router, app appx.App) []string {
	// rg records what is ACTUALLY mounted, in call order, so the returned list
	// cannot drift from the reg() sequence below; the parity test compares it
	// against routerNames, the independent transcription of Python's order.
	rg := &registrar{router: r}

	// --- reasoners/recon.py -------------------------------------------------
	reg(rg, NameRunIaCReader, func(ctx context.Context, in IaCReaderInput) (any, error) {
		// Python: result = await _run_iac_reader(runtime_router, repo_path)
		//         return result.model_dump()
		result, err := recon.RunIaCReader(ctx, app, in.RepoPath)
		if err != nil {
			return nil, err
		}
		return afx.Dump(result)
	})

	reg(rg, NameRunResourceGraphBuilder, func(ctx context.Context, in ResourceGraphBuilderInput) (any, error) {
		result, err := recon.RunResourceGraphBuilder(ctx, app, in.RepoPath, in.InventoryPath)
		if err != nil {
			return nil, err
		}
		return afx.Dump(result)
	})

	reg(rg, NameRunCloudConnector, func(ctx context.Context, in CloudConnectorInput) (any, error) {
		result, err := recon.RunCloudConnector(ctx, app, in.CloudConfig)
		if err != nil {
			return nil, err
		}
		return afx.Dump(result)
	})

	reg(rg, NameRunDriftDetector, func(ctx context.Context, in DriftDetectorInput) (any, error) {
		result, err := recon.RunDriftDetector(ctx, app, in.IaCGraphPath, in.CloudConfig)
		if err != nil {
			return nil, err
		}
		return afx.Dump(result)
	})

	// --- reasoners/hunt.py --------------------------------------------------
	// Python routes all seven through the shared `_run_hunter(runner, ...)`
	// helper; hunterHandler is that helper, with the runner bound per reasoner.
	reg(rg, NameRunIAMHunter, hunterHandler(app, hunt.RunIAMHunter))
	reg(rg, NameRunNetworkHunter, hunterHandler(app, hunt.RunNetworkHunter))
	reg(rg, NameRunDataHunter, hunterHandler(app, hunt.RunDataHunter))
	reg(rg, NameRunSecretsHunter, hunterHandler(app, hunt.RunSecretsHunter))
	reg(rg, NameRunComputeHunter, hunterHandler(app, hunt.RunComputeHunter))
	reg(rg, NameRunLoggingHunter, hunterHandler(app, hunt.RunLoggingHunter))
	reg(rg, NameRunComplianceHunter, hunterHandler(app, hunt.RunComplianceHunter))

	// --- reasoners/chain.py -------------------------------------------------
	reg(rg, NameRunPathConstructor, func(ctx context.Context, in PathConstructorInput) (any, error) {
		// Python:
		//   finding_models = [RawFinding.model_validate(f) for f in findings]
		//   drift_model = DriftReport.model_validate(drift_report) if drift_report is not None else None
		findings, err := bindEach[schemas.RawFinding](in.Findings)
		if err != nil {
			return nil, err
		}
		drift, err := bindOptional[schemas.DriftReport](in.DriftReport)
		if err != nil {
			return nil, err
		}
		result, err := chain.RunPathConstructor(ctx, app, findings, in.ResourceGraphPath, in.MaxPaths, in.MaxChildren, drift)
		if err != nil {
			return nil, err
		}
		return afx.Dump(result)
	})

	// --- reasoners/prove.py -------------------------------------------------
	reg(rg, NameRunStaticProver, proverHandler(app, prove.RunStaticProver))
	reg(rg, NameRunLiveProver, proverHandler(app, prove.RunLiveProver))

	// --- reasoners/remediate.py ---------------------------------------------
	reg(rg, NameRunFixGenerator, func(ctx context.Context, in FixGeneratorInput) (any, error) {
		// Python: finding_model = VerifiedFinding.model_validate(finding)
		finding, err := afx.Bind[schemas.VerifiedFinding](in.Finding)
		if err != nil {
			return nil, err
		}
		result, err := remediate.RunFixGenerator(ctx, app, in.RepoPath, finding)
		if err != nil {
			return nil, err
		}
		return afx.Dump(result)
	})

	// --- reasoners/phases.py ------------------------------------------------
	// The five phase bodies already return the exact map Python's model_dump()
	// (or literal dict) produces, so their handlers only bind + forward. NodeID
	// is read per call, matching internal/phases' documented divergence from
	// Python's import-time capture.
	reg(rg, NameReconPhase, func(ctx context.Context, in phases.ReconPhaseInput) (any, error) {
		return in.Run(ctx, app, phases.NodeID())
	})
	reg(rg, NameHuntPhase, func(ctx context.Context, in phases.HuntPhaseInput) (any, error) {
		return in.Run(ctx, app, phases.NodeID())
	})
	reg(rg, NameChainPhase, func(ctx context.Context, in phases.ChainPhaseInput) (any, error) {
		return in.Run(ctx, app, phases.NodeID())
	})
	reg(rg, NameProvePhase, func(ctx context.Context, in phases.ProvePhaseInput) (any, error) {
		return in.Run(ctx, app, phases.NodeID())
	})
	reg(rg, NameRemediationPhase, func(ctx context.Context, in phases.RemediationPhaseInput) (any, error) {
		return in.Run(ctx, app, phases.NodeID())
	})

	return rg.names
}

// registrar is the router plus the ordered record of what was registered on it.
// agent.Router keeps its entries unexported, so the bookkeeping lives here.
type registrar struct {
	router *agent.Router
	names  []string
}

// reg adapts a typed handler to the SDK's HandlerFunc by afx.BindHandlerInput-ing
// the request map into T, and registers it on rg.router, recording the name.
//
// BindHandlerInput, not plain Bind: the Python SDK validates every reasoner body
// against the signature before the coroutine runs
// (Agent._validate_handler_input, rendered as HTTP 422), and the Go SDK does
// not — it never reads a reasoner's InputSchema at execute time. Without that
// step the port diverged in BOTH directions: it accepted `run_iam_hunter {}`
// (binding every path to "") where Python answers "Missing required field:
// repo_path", and it rejected `tier: "2"` / `max_concurrent_hunters: "4"`,
// which Python coerces with int(). T's HandlerInputFields is the transcription
// of the signature; a T without one binds unvalidated.
//
// An afx.InputError is surfaced with Python's 422; any other bind failure stays
// a plain error, which the SDK renders as a failed execution.
//
// reg is also the ONE place the control-plane input schema is attached. Python
// derives it from the reasoner's signature; the Go SDK would otherwise publish
// the contentless `{"type":"object","additionalProperties":true}` default, so
// every registration carries MustInputSchema(name) — the schema the live Python
// node published for that same reasoner. Routing it through reg rather than
// spelling an option out at 20 call sites means a reasoner CANNOT be added here
// without one: a name the fixture does not cover panics on registration.
func reg[T any](rg *registrar, name string, fn func(context.Context, T) (any, error)) {
	rg.names = append(rg.names, name)
	rg.router.RegisterReasoner(name, func(ctx context.Context, input map[string]any) (any, error) {
		in, err := afx.BindHandlerInput[T](input)
		if err != nil {
			var inputErr *afx.InputError
			if errors.As(err, &inputErr) {
				return nil, inputErr.ExecuteError()
			}
			return nil, err
		}
		return fn(ctx, in)
	}, agent.WithInputSchema(MustInputSchema(name)))
}

// hunterFunc is the shared shape of the seven internal/agents/hunt entry points
// — the Go analogue of the `runner` parameter of hunt.py's `_run_hunter`.
type hunterFunc func(ctx context.Context, app appx.Harnesser, repoPath, resourceGraphPath, inventoryPath, depth string) (schemas.HuntResult, error)

// hunterHandler ports hunt.py's shared body:
//
//	result = await runner(app=_runtime_router, repo_path=..., resource_graph_path=...,
//	                      inventory_path=..., depth=...)
//	return result.model_dump()
func hunterHandler(app appx.Harnesser, runner hunterFunc) func(context.Context, HunterInput) (any, error) {
	return func(ctx context.Context, in HunterInput) (any, error) {
		result, err := runner(ctx, app, in.RepoPath, in.ResourceGraphPath, in.InventoryPath, in.Depth)
		if err != nil {
			return nil, err
		}
		return afx.Dump(result)
	}
}

// proverFunc is the shared shape of RunStaticProver / RunLiveProver.
//
// Python parity: prove.py calls `_run_<x>_prover(router, repo_path,
// finding_model, attack_path_model, tier)` — attack_path BEFORE tier. The Go
// agents package deliberately puts attackPath last (it is the optional one);
// the argument VALUES are identical either way.
type proverFunc func(ctx context.Context, app appx.Harnesser, repoPath string, finding schemas.RawFinding, tier int, attackPath *schemas.AttackPath) (schemas.VerifiedFinding, error)

// proverHandler ports the body prove.py's two reasoners share:
//
//	finding_model = RawFinding.model_validate(finding)
//	attack_path_model = AttackPath.model_validate(attack_path) if attack_path is not None else None
//	result = await _run_<x>_prover(_runtime_router, repo_path, finding_model, attack_path_model, tier)
//	return result.model_dump()
func proverHandler(app appx.Harnesser, runner proverFunc) func(context.Context, ProverInput) (any, error) {
	return func(ctx context.Context, in ProverInput) (any, error) {
		finding, err := afx.Bind[schemas.RawFinding](in.Finding)
		if err != nil {
			return nil, err
		}
		attackPath, err := bindOptional[schemas.AttackPath](in.AttackPath)
		if err != nil {
			return nil, err
		}
		result, err := runner(ctx, app, in.RepoPath, finding, in.Tier, attackPath)
		if err != nil {
			return nil, err
		}
		return afx.Dump(result)
	}
}

// bindEach ports `[Model.model_validate(x) for x in xs]`: a bind failure on any
// element aborts the whole reasoner, exactly as the list comprehension does.
// An empty input yields an empty (non-nil) slice, like Python's [].
func bindEach[T any](xs []map[string]any) ([]T, error) {
	out := make([]T, 0, len(xs))
	for _, x := range xs {
		v, err := afx.Bind[T](x)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// bindOptional ports `Model.model_validate(x) if x is not None else None`.
//
// Python parity: the guard is `is not None`, NOT truthiness — an EMPTY dict is
// not None, so it is validated into a fully defaulted model rather than
// collapsing to None. A nil Go map is the None case; a non-nil empty map takes
// the validate branch, matching.
func bindOptional[T any](x map[string]any) (*T, error) {
	if x == nil {
		return nil, nil
	}
	v, err := afx.Bind[T](x)
	if err != nil {
		return nil, err
	}
	return &v, nil
}
