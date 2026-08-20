package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/util"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/config"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// DefaultNodeID is the fallback in `os.getenv("NODE_ID", "cloudsecurity")`.
const DefaultNodeID = config.DefaultNodeID

// CheckpointDirName is the `.cloudsecurity` directory `self.repo_path /
// ".cloudsecurity"` names.
const CheckpointDirName = ".cloudsecurity"

// PhaseOrder ports ScanOrchestrator._PHASE_ORDER. It seeds cost_breakdown's
// keys, so its ORDER is observable in the scan result's cost_breakdown dict in
// Python (insertion-ordered). A Go map cannot carry that order, so the single
// declaration lives in schemas next to the field and every renderer
// (internal/output's report and JSON artifacts) walks it from there rather than
// sorting.
var PhaseOrder = schemas.CostBreakdownOrder

// ScanOrchestrator ports orchestrator.py ScanOrchestrator.
//
// Field names follow the Python attributes one for one. Everything Python
// mutates from the outside (app.py rewrites repo_path and checkpoint_dir after
// construction) is exported.
type ScanOrchestrator struct {
	// App is Python's `self.app = cast("Any", app)`.
	App appx.App
	// Input is Python's `self.input`.
	Input schemas.CloudSecurityInput

	// StartedAt is `self.started_at = time.monotonic()`.
	StartedAt time.Time
	// RepoPath is `Path(os.getenv("CLOUDSECURITY_REPO_PATH", os.getcwd())).resolve()`,
	// which app.py then OVERWRITES with the resolved repo checkout.
	RepoPath string
	// CheckpointDir is `self.repo_path / ".cloudsecurity"`, likewise rewritten
	// by app.py.
	CheckpointDir string

	// Config is `ScanConfig.from_input(self.input, str(self.repo_path))`.
	Config config.ScanConfig
	// BudgetConfig is `self.config.budget`.
	BudgetConfig config.BudgetConfig

	MaxCostUSD         *float64
	MaxDurationSeconds *int

	TotalCostUSD     float64
	CostBreakdown    map[string]float64
	AgentInvocations int
	BudgetExhausted  bool

	FindingsNotVerified int

	// nowFn is the test seam behind both time.monotonic() and
	// datetime.now(UTC). Never nil after New; NewWithClock injects a stub.
	nowFn func() time.Time
}

// New ports `ScanOrchestrator(app=app, input=input)`.
//
// Python:
//
//	self.started_at = time.monotonic()
//	self.repo_path = Path(os.getenv("CLOUDSECURITY_REPO_PATH", os.getcwd())).resolve()
//	self.checkpoint_dir = self.repo_path / ".cloudsecurity"
//	self.config = ScanConfig.from_input(self.input, str(self.repo_path))
//	self.budget_config = self.config.budget
//	self.max_cost_usd = input.max_cost_usd
//	self.max_duration_seconds = input.max_duration_seconds
//	self.total_cost_usd = 0.0
//	self.cost_breakdown = {phase: 0.0 for phase in self._PHASE_ORDER}
//	self.agent_invocations = 0
//	self.budget_exhausted = False
//	self.findings_not_verified = 0
//
// Python parity: ScanConfig.from_input parses `depth` with the STRICT
// DepthProfile constructor, so an unrecognized depth raises a ValueError here —
// before run() is ever awaited. app.py's try/except only wraps run(), so that
// ValueError escapes as a 500 rather than the 400 the depth error looks like it
// should be. The Go port returns the error from New for the node to map, and
// the node must reproduce whichever status it wants deliberately.
func New(app appx.App, input schemas.CloudSecurityInput) (*ScanOrchestrator, error) {
	return NewWithClock(app, input, time.Now)
}

// NewWithClock is New with an injectable clock, used by tests to make
// duration_seconds and timestamp deterministic. nowFn nil means time.Now.
func NewWithClock(app appx.App, input schemas.CloudSecurityInput, nowFn func() time.Time) (*ScanOrchestrator, error) {
	if nowFn == nil {
		nowFn = time.Now
	}

	repoPath, err := defaultRepoPath()
	if err != nil {
		return nil, err
	}

	cfg, err := config.ScanConfigFromInput(input, repoPath)
	if err != nil {
		return nil, err
	}

	costBreakdown := make(map[string]float64, len(PhaseOrder))
	for _, phase := range PhaseOrder {
		costBreakdown[phase] = 0.0
	}

	return &ScanOrchestrator{
		App:                 app,
		Input:               input,
		StartedAt:           nowFn(),
		RepoPath:            repoPath,
		CheckpointDir:       filepath.Join(repoPath, CheckpointDirName),
		Config:              cfg,
		BudgetConfig:        cfg.Budget,
		MaxCostUSD:          input.MaxCostUSD,
		MaxDurationSeconds:  input.MaxDurationSeconds,
		TotalCostUSD:        0.0,
		CostBreakdown:       costBreakdown,
		AgentInvocations:    0,
		BudgetExhausted:     false,
		FindingsNotVerified: 0,
		nowFn:               nowFn,
	}, nil
}

// defaultRepoPath ports
// `Path(os.getenv("CLOUDSECURITY_REPO_PATH", os.getcwd())).resolve()`.
//
// Python parity: os.getenv substitutes the default only when the key is ABSENT,
// so CLOUDSECURITY_REPO_PATH="" yields Path("") — which is Path(".") — and
// resolves to the cwd anyway. util.ResolvePath("") does the same.
func defaultRepoPath() (string, error) {
	raw, present := os.LookupEnv("CLOUDSECURITY_REPO_PATH")
	if !present {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("orch: resolve repo path: %w", err)
		}
		raw = cwd
	}
	return util.ResolvePath(raw), nil
}

// SetCheckpointDirFromRepoPath re-derives CheckpointDir from the current
// RepoPath. app.py does exactly this after overwriting repo_path:
//
//	orchestrator.repo_path = Path(repo_path)
//	orchestrator.checkpoint_dir = orchestrator.repo_path / ".cloudsecurity"
//
// Python parity: app.py does NOT re-run ScanConfig.from_input, so Config.RepoPath
// keeps pointing at the CLOUDSECURITY_REPO_PATH/cwd value. Nothing reads it, but
// the staleness is real and is reproduced rather than fixed.
func (o *ScanOrchestrator) SetCheckpointDirFromRepoPath() {
	o.CheckpointDir = filepath.Join(o.RepoPath, CheckpointDirName)
}

// NodeID ports `node_id = os.getenv("NODE_ID", "cloudsecurity")` — read inside
// run(), not at import.
//
// It delegates to config.NodeID for the same reason internal/phases does: the
// prefix of the five phase Call targets must be resolved by the identical rule
// internal/node uses for the id the agent registers under, or the orchestrator
// can emit ".recon_phase" against a node registered as "cloudsecurity".
func NodeID() string { return config.NodeID() }

// errMissingVerifiedKey reproduces the KeyError Python raises when a phase's
// reply has no "verified" key. app.py renders it as
// `scan execution failed: 'verified'`, because str(KeyError("verified")) is the
// REPR of the key, quotes included.
var errMissingVerifiedKey = errors.New("'verified'")

// Run ports ScanOrchestrator.run(): the five sequential phase calls, their
// duration bookkeeping, their checkpoints and the final output generation.
func (o *ScanOrchestrator) Run(ctx context.Context) (schemas.CloudSecurityScanResult, error) {
	var zero schemas.CloudSecurityScanResult
	nodeID := NodeID()

	// --- RECON -------------------------------------------------------------
	var cloudConfig any
	if o.Input.Cloud != nil {
		dumped, err := afx.ToMap(*o.Input.Cloud)
		if err != nil {
			return zero, err
		}
		cloudConfig = dumped
	}
	recon, err := callModel[schemas.ReconResult](ctx, o.App,
		nodeID+".recon_phase", "recon_phase",
		map[string]any{
			"repo_path":    o.RepoPath,
			"depth":        string(o.Config.Depth),
			"tier":         o.Config.Tier,
			"cloud_config": cloudConfig,
		})
	if err != nil {
		return zero, err
	}
	recon.ReconDurationSeconds = o.elapsedSeconds()
	if err := o.WriteCheckpoint("recon", recon); err != nil {
		return zero, err
	}
	o.EmitProgress("recon", 1, 1, 0)

	// --- HUNT --------------------------------------------------------------
	hunt, err := callModel[schemas.HuntResult](ctx, o.App,
		nodeID+".hunt_phase", "hunt_phase",
		map[string]any{
			"repo_path":              o.RepoPath,
			"resource_graph_path":    recon.ResourceGraph.GraphSavedPath,
			"inventory_path":         recon.Inventory.InventorySavedPath,
			"depth":                  string(o.Config.Depth),
			"max_concurrent_hunters": o.BudgetConfig.MaxConcurrentHunters,
		})
	if err != nil {
		return zero, err
	}
	hunt.HuntDurationSeconds = o.elapsedSeconds() - recon.ReconDurationSeconds
	if err := o.WriteCheckpoint("hunt", hunt); err != nil {
		return zero, err
	}
	o.EmitProgress("hunt", 1, 1, len(hunt.Findings))

	// --- CHAIN -------------------------------------------------------------
	findingDumps := make([]map[string]any, 0, len(hunt.Findings))
	for _, f := range hunt.Findings {
		dumped, dumpErr := afx.ToMap(f)
		if dumpErr != nil {
			return zero, dumpErr
		}
		findingDumps = append(findingDumps, dumped)
	}
	var driftReport any
	if recon.DriftReport != nil {
		dumped, dumpErr := afx.ToMap(*recon.DriftReport)
		if dumpErr != nil {
			return zero, dumpErr
		}
		driftReport = dumped
	}
	chain, err := callModel[schemas.ChainResult](ctx, o.App,
		nodeID+".chain_phase", "chain_phase",
		map[string]any{
			"findings":            findingDumps,
			"resource_graph_path": recon.ResourceGraph.GraphSavedPath,
			"drift_report":        driftReport,
			"depth":               string(o.Config.Depth),
			"max_children":        o.BudgetConfig.MaxConcurrentChainChildren,
		})
	if err != nil {
		return zero, err
	}
	if err := o.WriteCheckpoint("chain", chain); err != nil {
		return zero, err
	}

	// --- PROVE -------------------------------------------------------------
	huntDump, err := afx.ToMap(hunt)
	if err != nil {
		return zero, err
	}
	chainDump, err := afx.ToMap(chain)
	if err != nil {
		return zero, err
	}
	proveDict, err := callDict(ctx, o.App,
		nodeID+".prove_phase", "prove_phase",
		map[string]any{
			"repo_path":              o.RepoPath,
			"hunt_result":            huntDump,
			"chain_result":           chainDump,
			"depth":                  string(o.Config.Depth),
			"tier":                   o.Config.Tier,
			"max_concurrent_provers": o.BudgetConfig.MaxConcurrentProvers,
		})
	if err != nil {
		return zero, err
	}
	verified, err := bindVerifiedList(proveDict)
	if err != nil {
		return zero, err
	}
	o.FindingsNotVerified = intFromPayload(proveDict, "not_verified", 0)
	if err := o.WriteCheckpointList("prove", verified); err != nil {
		return zero, err
	}

	// --- REMEDIATION -------------------------------------------------------
	verifiedDumps := make([]map[string]any, 0, len(verified))
	for _, v := range verified {
		dumped, dumpErr := afx.ToMap(v)
		if dumpErr != nil {
			return zero, dumpErr
		}
		verifiedDumps = append(verifiedDumps, dumped)
	}
	remediationDict, err := callDict(ctx, o.App,
		nodeID+".remediation_phase", "remediation_phase",
		map[string]any{
			"repo_path":         o.RepoPath,
			"verified_findings": verifiedDumps,
		})
	if err != nil {
		return zero, err
	}
	verified, err = bindVerifiedList(remediationDict)
	if err != nil {
		return zero, err
	}

	// Python parity: agent_invocations is ASSIGNED here, discarding whatever
	// the (unreachable) _PhaseHarnessProxy accumulated. The "+ 5" is the five
	// phase reasoners themselves.
	o.AgentInvocations = intFromPayload(proveDict, "total_selected", 0) + len(hunt.StrategiesRun) + 5

	return o.GenerateOutput(recon, hunt, chain, verified), nil
}

// elapsedSeconds ports `time.monotonic() - self.started_at`.
func (o *ScanOrchestrator) elapsedSeconds() float64 {
	return o.nowFn().Sub(o.StartedAt).Seconds()
}

// nowUTC ports `datetime.now(UTC)`.
func (o *ScanOrchestrator) nowUTC() schemas.Timestamp {
	return schemas.NewTimestamp(o.nowFn().UTC())
}

// unwrapDict ports `_as_dict(_unwrap(raw, name), name)` — the orchestrator's own
// copy of the strict pair, byte-identical to reasoners/phases.py's.
func unwrapDict(raw any, name string) (map[string]any, error) {
	payload, err := afx.UnwrapStrict(raw, name)
	if err != nil {
		return nil, err
	}
	return afx.AsMap(payload, name)
}

// callDict performs one phase call and returns the unwrapped reply dict.
func callDict(ctx context.Context, app appx.Caller, target, name string, kwargs map[string]any) (map[string]any, error) {
	raw, err := app.Call(ctx, target, kwargs)
	if err != nil {
		return nil, err
	}
	return unwrapDict(raw, name)
}

// callModel is callDict plus `Model.model_validate(...)`.
func callModel[T any](ctx context.Context, app appx.Caller, target, name string, kwargs map[string]any) (T, error) {
	var zero T
	payload, err := callDict(ctx, app, target, name, kwargs)
	if err != nil {
		return zero, err
	}
	return afx.Bind[T](payload)
}

// bindVerifiedList ports
// `[VerifiedFinding.model_validate(v) for v in payload["verified"]]`
// (orchestrator.py:121 and :131).
//
// Python parity: the subscript is a plain `[...]`, so a missing key is a
// KeyError, not a silent empty list — hence errMissingVerifiedKey rather than a
// nil result. That is NOT ValueError-class, so app.py answers it 500.
//
// Each element goes through afx.Bind, not a bulk json.Unmarshal into
// []VerifiedFinding. Bind is what carries the other half of model_validate —
// pydantic's REQUIRED-field check (VerifiedFinding declares title, verdict,
// severity and category, none of which has a default). A bulk decode accepts
// `{"id": "x", "iac_file": "main.tf"}` and yields a finding whose verdict is ""
// — uncounted in the verdict tallies, a bogus "" key in by_severity, and
// dropped outright by the default severity_threshold — where the repo venv
// raises `4 validation errors for VerifiedFinding`. Every failure Bind reports
// is an *afx.ValidationError, i.e. ValueError-class, so it reaches app.py's
// 400 branch exactly as pydantic's ValidationError does. Verified against the
// venv: model_validate of a dict missing required keys, of a bad `verdict`
// enum, and of a non-dict are all ValidationError (a ValueError subclass).
//
// The JSON round trip tolerates both `[]any` (what the control plane hands
// back) and a typed slice (what a test fake may hand back); UseNumber keeps
// integer literals inside the models' free-form fields integral, matching every
// other Bind site.
//
// DIVERGENCE (unreachable): a `verified` value that is neither a list nor a
// JSON array — a dict, say — makes Python iterate its KEYS and raise
// ValidationError per key (400); the decode below fails instead and takes the
// 500 branch. prove_phase always replies with a list.
func bindVerifiedList(payload map[string]any) ([]schemas.VerifiedFinding, error) {
	raw, present := payload["verified"]
	if !present {
		return nil, errMissingVerifiedKey
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("orch: encode verified findings: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.UseNumber()
	var elements []any
	if err := dec.Decode(&elements); err != nil {
		return nil, fmt.Errorf("orch: decode verified findings: %w", err)
	}
	out := make([]schemas.VerifiedFinding, 0, len(elements))
	for _, element := range elements {
		obj, ok := element.(map[string]any)
		if !ok {
			// pydantic: "Input should be a valid dictionary or instance of
			// VerifiedFinding" — a ValidationError, hence ValueError-class.
			return nil, &afx.ValidationError{
				Err: fmt.Errorf("1 validation error for VerifiedFinding: Input should be a valid dictionary or instance of VerifiedFinding, got %T", element),
			}
		}
		bound, err := afx.Bind[schemas.VerifiedFinding](obj)
		if err != nil {
			return nil, err
		}
		out = append(out, bound)
	}
	return out, nil
}

// intFromPayload ports `payload.get(key, default)` for the two integer counters
// the orchestrator reads out of prove_phase's reply.
//
// Python parity caveat: Python takes whatever the key holds, so a float 3.0
// would flow into `agent_invocations` as a float. Every value here crosses the
// control plane as JSON — where the phase wrote a Go int — so it arrives as a
// JSON number that Go decodes to float64; the conversion back to int is exact
// for every value the phase can produce. A non-numeric value (which Python
// would blow up on, one line later) falls back to the default.
func intFromPayload(payload map[string]any, key string, def int) int {
	raw, present := payload[key]
	if !present {
		return def
	}
	switch v := raw.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float32:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
		if f, err := v.Float64(); err == nil {
			return int(f)
		}
	}
	return def
}
