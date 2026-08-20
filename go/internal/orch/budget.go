package orch

import (
	"context"

	"github.com/Agent-Field/agentfield/sdk/go/harness"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// BudgetExhausted ports `class BudgetExhausted(RuntimeError)`. Its message is
// f"{phase} budget exhausted", verbatim.
type BudgetExhausted struct {
	Phase string
}

func (e *BudgetExhausted) Error() string { return e.Phase + " budget exhausted" }

// defaultPhaseBudgetWeight is the `weights.get(phase, 0.1)` fallback in
// _phase_budget_limit — reachable only for a phase name outside _PHASE_ORDER.
const defaultPhaseBudgetWeight = 0.1

// BudgetOrTimeoutExhausted ports _budget_or_timeout_exhausted.
//
// Python:
//
//	if self.max_duration_seconds is not None:
//	    if time.monotonic() - self.started_at > self.max_duration_seconds:
//	        self.budget_exhausted = True; return True
//	if self.max_cost_usd is not None and self.total_cost_usd >= self.max_cost_usd:
//	    self.budget_exhausted = True; return True
//	phase_limit = self._phase_budget_limit(phase)
//	if phase_limit is not None and self.cost_breakdown.get(phase, 0.0) >= phase_limit:
//	    self.budget_exhausted = True; return True
//	return False
//
// Python parity: the duration test is STRICTLY greater while both cost tests are
// greater-or-equal, and the method has the side effect of latching
// budget_exhausted.
func (o *ScanOrchestrator) BudgetOrTimeoutExhausted(phase string) bool {
	if o.MaxDurationSeconds != nil {
		if o.elapsedSeconds() > float64(*o.MaxDurationSeconds) {
			o.BudgetExhausted = true
			return true
		}
	}
	if o.MaxCostUSD != nil && o.TotalCostUSD >= *o.MaxCostUSD {
		o.BudgetExhausted = true
		return true
	}
	if limit := o.PhaseBudgetLimit(phase); limit != nil {
		if o.CostBreakdown[phase] >= *limit {
			o.BudgetExhausted = true
			return true
		}
	}
	return false
}

// PhaseBudgetLimit ports _phase_budget_limit: nil (Python None) when there is no
// overall cost cap, otherwise max_cost_usd scaled by the phase's budget
// percentage.
func (o *ScanOrchestrator) PhaseBudgetLimit(phase string) *float64 {
	if o.MaxCostUSD == nil {
		return nil
	}
	weights := map[string]float64{
		"recon":     o.BudgetConfig.ReconBudgetPct,
		"hunt":      o.BudgetConfig.HuntBudgetPct,
		"chain":     o.BudgetConfig.ChainBudgetPct,
		"prove":     o.BudgetConfig.ProveBudgetPct,
		"remediate": o.BudgetConfig.RemediateBudgetPct,
	}
	weight, present := weights[phase]
	if !present {
		weight = defaultPhaseBudgetWeight
	}
	limit := *o.MaxCostUSD * weight
	return &limit
}

// RegisterCost ports _register_cost:
//
//	if cost_usd is None or cost_usd < 0: return
//	self.total_cost_usd += cost_usd
//	self.cost_breakdown[phase] = self.cost_breakdown.get(phase, 0.0) + cost_usd
//
// Python parity: a nil cost (the harness reported none) and a NEGATIVE cost are
// both ignored, and a phase name outside _PHASE_ORDER creates a new
// cost_breakdown entry rather than erroring.
func (o *ScanOrchestrator) RegisterCost(phase string, costUSD *float64) {
	if costUSD == nil || *costUSD < 0 {
		return
	}
	o.TotalCostUSD += *costUSD
	if o.CostBreakdown == nil {
		o.CostBreakdown = map[string]float64{}
	}
	o.CostBreakdown[phase] += *costUSD
}

// EmitProgress ports _emit_progress.
//
// Python builds a ScanProgress and then DOES NOTHING WITH IT — there is no
// app.note, no return, no side effect beyond the arithmetic. The port keeps the
// arithmetic (and returns the value so it is testable) but emits nothing, which
// is the observable behaviour that matters: the Python node produces no
// progress note, so neither may the Go node.
//
//	elapsed = time.monotonic() - self.started_at
//	safe_total = max(1, agents_total)
//	phase_progress = min(1.0, agents_completed / safe_total)
//	estimated_total = elapsed / phase_progress if phase_progress > 0 else elapsed
//	ScanProgress(..., agents_running=max(0, agents_total - agents_completed),
//	             estimated_remaining_seconds=max(0.0, estimated_total - elapsed),
//	             cost_so_far_usd=round(self.total_cost_usd, 4))
func (o *ScanOrchestrator) EmitProgress(phase string, agentsTotal, agentsCompleted, findingsSoFar int) schemas.ScanProgress {
	elapsed := o.elapsedSeconds()

	safeTotal := agentsTotal
	if safeTotal < 1 {
		safeTotal = 1
	}
	phaseProgress := float64(agentsCompleted) / float64(safeTotal)
	if phaseProgress > 1.0 {
		phaseProgress = 1.0
	}

	estimatedTotal := elapsed
	if phaseProgress > 0 {
		estimatedTotal = elapsed / phaseProgress
	}

	agentsRunning := agentsTotal - agentsCompleted
	if agentsRunning < 0 {
		agentsRunning = 0
	}
	remaining := estimatedTotal - elapsed
	if remaining < 0.0 {
		remaining = 0.0
	}

	progress := schemas.NewScanProgress()
	progress.Phase = phase
	progress.PhaseProgress = phaseProgress
	progress.AgentsTotal = agentsTotal
	progress.AgentsCompleted = agentsCompleted
	progress.AgentsRunning = agentsRunning
	progress.FindingsSoFar = findingsSoFar
	progress.ElapsedSeconds = elapsed
	progress.EstimatedRemainingSeconds = remaining
	progress.CostSoFarUSD = pyfmt.Round(o.TotalCostUSD, 4)
	return progress
}

// PhaseHarnessProxy ports `class _PhaseHarnessProxy`: an app.harness facade that
// refuses to run once the phase's budget is spent and books the cost of every
// run it does allow.
//
// It is DEAD CODE in Python — run() never constructs one — and is ported for
// completeness because it is the only place the budget helpers are wired to
// anything. It satisfies appx.Harnesser so it can be dropped in wherever an
// agent function takes the harness seam.
type PhaseHarnessProxy struct {
	orchestrator *ScanOrchestrator
	phase        string
}

var _ appx.Harnesser = (*PhaseHarnessProxy)(nil)

// NewPhaseHarnessProxy ports `_PhaseHarnessProxy(orchestrator, phase)`.
func NewPhaseHarnessProxy(orchestrator *ScanOrchestrator, phase string) *PhaseHarnessProxy {
	return &PhaseHarnessProxy{orchestrator: orchestrator, phase: phase}
}

// Harness ports _PhaseHarnessProxy.harness.
//
// Python:
//
//	if self._orchestrator._budget_or_timeout_exhausted(self._phase):
//	    raise BudgetExhausted(f"{self._phase} budget exhausted")
//	result = await self._orchestrator.app.harness(prompt, schema=schema, cwd=cwd, **kwargs)
//	self._orchestrator.agent_invocations += 1
//	self._orchestrator._register_cost(self._phase, getattr(result, "cost_usd", None))
//	return result
//
// Python parity: a harness that RAISES bumps neither the invocation counter nor
// the cost, because the await propagates before those two lines run. A harness
// that returns an ERROR result (IsError set, no Go error) does bump both, since
// Python's SDK returns that as a value too.
func (p *PhaseHarnessProxy) Harness(
	ctx context.Context,
	prompt string,
	schema map[string]any,
	dest any,
	opts harness.Options,
) (*harness.Result, error) {
	if p.orchestrator.BudgetOrTimeoutExhausted(p.phase) {
		return nil, &BudgetExhausted{Phase: p.phase}
	}
	result, err := p.orchestrator.App.Harness(ctx, prompt, schema, dest, opts)
	if err != nil {
		return nil, err
	}
	p.orchestrator.AgentInvocations++
	var costUSD *float64
	if result != nil {
		costUSD = result.CostUSD
	}
	p.orchestrator.RegisterCost(p.phase, costUSD)
	return result, nil
}
