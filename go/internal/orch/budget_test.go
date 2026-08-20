package orch

import (
	"context"
	"errors"
	"testing"
	"time"

	sdkharness "github.com/Agent-Field/agentfield/sdk/go/harness"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// TestBudgetExhaustedError pins the RuntimeError message
// f"{phase} budget exhausted".
func TestBudgetExhaustedError(t *testing.T) {
	err := &BudgetExhausted{Phase: "hunt"}
	if err.Error() != "hunt budget exhausted" {
		t.Fatalf("Error() = %q", err.Error())
	}
	var target *BudgetExhausted
	if !errors.As(error(err), &target) {
		t.Fatal("BudgetExhausted should be matchable with errors.As")
	}
}

// TestBudgetOrTimeoutExhausted covers each of the three arms plus the
// all-clear path, and the budget_exhausted latch.
func TestBudgetOrTimeoutExhausted(t *testing.T) {
	t.Run("no caps means never exhausted", func(t *testing.T) {
		o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
		if o.BudgetOrTimeoutExhausted("hunt") {
			t.Fatal("exhausted with no caps")
		}
		if o.BudgetExhausted {
			t.Fatal("latch set with no caps")
		}
	})

	t.Run("duration cap is strictly greater", func(t *testing.T) {
		input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.MaxDurationSeconds = intPtr(1) })
		// Each nowFn call advances 1s: StartedAt = t0, first check sees +1s
		// (NOT > 1), second sees +2s (> 1).
		o := newTestOrchestrator(t, &appx.Fake{}, input, steppingClock(time.Second))
		if o.BudgetOrTimeoutExhausted("hunt") {
			t.Fatal("elapsed == cap must NOT be exhausted (Python uses >)")
		}
		if !o.BudgetOrTimeoutExhausted("hunt") {
			t.Fatal("elapsed > cap must be exhausted")
		}
		if !o.BudgetExhausted {
			t.Fatal("budget_exhausted latch not set")
		}
	})

	t.Run("total cost cap is greater or equal", func(t *testing.T) {
		input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.MaxCostUSD = floatPtr(1.0) })
		o := newTestOrchestrator(t, &appx.Fake{}, input, fixedClock())
		o.TotalCostUSD = 0.99
		if o.BudgetOrTimeoutExhausted("hunt") {
			t.Fatal("below the cap must not be exhausted")
		}
		o.TotalCostUSD = 1.0
		if !o.BudgetOrTimeoutExhausted("hunt") {
			t.Fatal("cost == cap must be exhausted (Python uses >=)")
		}
	})

	t.Run("per phase cap", func(t *testing.T) {
		input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.MaxCostUSD = floatPtr(1.0) })
		o := newTestOrchestrator(t, &appx.Fake{}, input, fixedClock())
		// hunt's share is 35% of 1.0.
		o.CostBreakdown["hunt"] = 0.34
		if o.BudgetOrTimeoutExhausted("hunt") {
			t.Fatal("below the phase cap must not be exhausted")
		}
		o.CostBreakdown["hunt"] = 0.35
		if !o.BudgetOrTimeoutExhausted("hunt") {
			t.Fatal("phase cost == phase cap must be exhausted")
		}
	})
}

// TestPhaseBudgetLimit pins the five weights and the 0.1 fallback, plus the
// None-when-uncapped rule.
func TestPhaseBudgetLimit(t *testing.T) {
	t.Run("nil without a cost cap", func(t *testing.T) {
		o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
		if got := o.PhaseBudgetLimit("hunt"); got != nil {
			t.Fatalf("PhaseBudgetLimit = %v, want nil", *got)
		}
	})

	input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.MaxCostUSD = floatPtr(10.0) })
	o := newTestOrchestrator(t, &appx.Fake{}, input, fixedClock())
	cases := map[string]float64{
		"recon":     1.0,
		"hunt":      3.5,
		"chain":     2.0,
		"prove":     2.5,
		"remediate": 1.0,
		"unknown":   1.0, // weights.get(phase, 0.1)
	}
	for phase, want := range cases {
		got := o.PhaseBudgetLimit(phase)
		if got == nil {
			t.Fatalf("PhaseBudgetLimit(%q) = nil", phase)
		}
		if diff := *got - want; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("PhaseBudgetLimit(%q) = %v, want %v", phase, *got, want)
		}
	}
}

// TestRegisterCost covers `if cost_usd is None or cost_usd < 0: return`.
func TestRegisterCost(t *testing.T) {
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())

	o.RegisterCost("hunt", nil)
	o.RegisterCost("hunt", floatPtr(-1.0))
	if o.TotalCostUSD != 0 || o.CostBreakdown["hunt"] != 0 {
		t.Fatalf("nil / negative costs must be ignored: %v %v", o.TotalCostUSD, o.CostBreakdown["hunt"])
	}

	o.RegisterCost("hunt", floatPtr(0.0))
	o.RegisterCost("hunt", floatPtr(0.25))
	o.RegisterCost("hunt", floatPtr(0.25))
	if o.TotalCostUSD != 0.5 || o.CostBreakdown["hunt"] != 0.5 {
		t.Fatalf("total/hunt = %v/%v, want 0.5/0.5", o.TotalCostUSD, o.CostBreakdown["hunt"])
	}

	// A phase outside _PHASE_ORDER gets a fresh bucket (dict.get(phase, 0.0)).
	o.RegisterCost("mystery", floatPtr(1.5))
	if o.CostBreakdown["mystery"] != 1.5 {
		t.Fatalf("cost_breakdown[mystery] = %v", o.CostBreakdown["mystery"])
	}
}

// TestEmitProgress covers the arithmetic and the fact that NOTHING is emitted.
func TestEmitProgress(t *testing.T) {
	fake := &appx.Fake{}
	o := newTestOrchestrator(t, fake, scanInput(t, nil), steppingClock(2*time.Second))
	o.TotalCostUSD = 0.123456

	// First nowFn call was StartedAt; this one is +2s.
	got := o.EmitProgress("hunt", 4, 1, 7)
	if got.Phase != "hunt" || got.AgentsTotal != 4 || got.AgentsCompleted != 1 || got.FindingsSoFar != 7 {
		t.Fatalf("progress = %#v", got)
	}
	if got.AgentsRunning != 3 {
		t.Errorf("agents_running = %d, want 3", got.AgentsRunning)
	}
	if got.PhaseProgress != 0.25 {
		t.Errorf("phase_progress = %v, want 0.25", got.PhaseProgress)
	}
	if got.ElapsedSeconds != 2.0 {
		t.Errorf("elapsed_seconds = %v, want 2", got.ElapsedSeconds)
	}
	// estimated_total = 2 / 0.25 = 8 -> remaining = 6.
	if got.EstimatedRemainingSeconds != 6.0 {
		t.Errorf("estimated_remaining_seconds = %v, want 6", got.EstimatedRemainingSeconds)
	}
	if got.CostSoFarUSD != 0.1235 {
		t.Errorf("cost_so_far_usd = %v, want 0.1235", got.CostSoFarUSD)
	}
	if len(fake.Notes) != 0 {
		t.Fatalf("_emit_progress must not emit a note, got %v", fake.NoteMessages())
	}
}

// TestEmitProgress_EdgeCases covers max(1, agents_total), the min(1.0, ...)
// clamp, the phase_progress == 0 branch and max(0, ...) on both derived fields.
func TestEmitProgress_EdgeCases(t *testing.T) {
	t.Run("zero agents_total is clamped to one", func(t *testing.T) {
		o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
		got := o.EmitProgress("recon", 0, 1, 0)
		if got.PhaseProgress != 1.0 {
			t.Fatalf("phase_progress = %v, want 1.0", got.PhaseProgress)
		}
		if got.AgentsRunning != 0 {
			t.Fatalf("agents_running = %d, want 0", got.AgentsRunning)
		}
	})

	t.Run("progress is capped at one", func(t *testing.T) {
		o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
		got := o.EmitProgress("recon", 2, 5, 0)
		if got.PhaseProgress != 1.0 {
			t.Fatalf("phase_progress = %v, want 1.0", got.PhaseProgress)
		}
		if got.AgentsRunning != 0 {
			t.Fatalf("agents_running = %d, want 0 (max(0, 2-5))", got.AgentsRunning)
		}
	})

	t.Run("zero progress leaves nothing remaining", func(t *testing.T) {
		o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), steppingClock(3*time.Second))
		got := o.EmitProgress("recon", 4, 0, 0)
		if got.PhaseProgress != 0 {
			t.Fatalf("phase_progress = %v", got.PhaseProgress)
		}
		// estimated_total = elapsed -> remaining = 0.
		if got.EstimatedRemainingSeconds != 0 {
			t.Fatalf("estimated_remaining_seconds = %v, want 0", got.EstimatedRemainingSeconds)
		}
	})
}

// TestPhaseHarnessProxy covers the budget gate, the invocation counter and the
// cost bookkeeping.
func TestPhaseHarnessProxy(t *testing.T) {
	t.Run("refuses once the budget is spent", func(t *testing.T) {
		input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.MaxCostUSD = floatPtr(1.0) })
		fake := &appx.Fake{}
		o := newTestOrchestrator(t, fake, input, fixedClock())
		o.TotalCostUSD = 1.0

		proxy := NewPhaseHarnessProxy(o, "hunt")
		_, err := proxy.Harness(context.Background(), "p", nil, nil, sdkharness.Options{})
		var exhausted *BudgetExhausted
		if !errors.As(err, &exhausted) || exhausted.Phase != "hunt" {
			t.Fatalf("err = %v, want a BudgetExhausted for hunt", err)
		}
		if len(fake.Harnesses) != 0 {
			t.Fatal("the harness must not run once the budget is spent")
		}
		if o.AgentInvocations != 0 {
			t.Fatalf("agent_invocations = %d", o.AgentInvocations)
		}
	})

	t.Run("counts invocations and registers cost", func(t *testing.T) {
		cost := 0.4
		fake := &appx.Fake{HarnessFn: func(_ context.Context, _ string, _ map[string]any, _ any, _ sdkharness.Options) (*sdkharness.Result, error) {
			return &sdkharness.Result{Result: "ok", CostUSD: &cost}, nil
		}}
		o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
		proxy := NewPhaseHarnessProxy(o, "prove")

		for i := 0; i < 2; i++ {
			if _, err := proxy.Harness(context.Background(), "p", nil, nil, sdkharness.Options{}); err != nil {
				t.Fatalf("Harness: %v", err)
			}
		}
		if o.AgentInvocations != 2 {
			t.Errorf("agent_invocations = %d, want 2", o.AgentInvocations)
		}
		if o.TotalCostUSD != 0.8 {
			t.Errorf("total_cost_usd = %v, want 0.8", o.TotalCostUSD)
		}
		if o.CostBreakdown["prove"] != 0.8 {
			t.Errorf("cost_breakdown[prove] = %v, want 0.8", o.CostBreakdown["prove"])
		}
	})

	t.Run("a harness error bumps nothing", func(t *testing.T) {
		fake := &appx.Fake{HarnessFn: func(_ context.Context, _ string, _ map[string]any, _ any, _ sdkharness.Options) (*sdkharness.Result, error) {
			return nil, errors.New("harness blew up")
		}}
		o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
		proxy := NewPhaseHarnessProxy(o, "recon")
		if _, err := proxy.Harness(context.Background(), "p", nil, nil, sdkharness.Options{}); err == nil {
			t.Fatal("expected the harness error to propagate")
		}
		if o.AgentInvocations != 0 || o.TotalCostUSD != 0 {
			t.Fatalf("counters moved: %d / %v", o.AgentInvocations, o.TotalCostUSD)
		}
	})

	t.Run("a nil cost is ignored but still counts as an invocation", func(t *testing.T) {
		fake := &appx.Fake{HarnessFn: func(_ context.Context, _ string, _ map[string]any, _ any, _ sdkharness.Options) (*sdkharness.Result, error) {
			return &sdkharness.Result{Result: "ok"}, nil
		}}
		o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
		proxy := NewPhaseHarnessProxy(o, "chain")
		if _, err := proxy.Harness(context.Background(), "p", nil, nil, sdkharness.Options{}); err != nil {
			t.Fatalf("Harness: %v", err)
		}
		if o.AgentInvocations != 1 || o.TotalCostUSD != 0 {
			t.Fatalf("counters = %d / %v", o.AgentInvocations, o.TotalCostUSD)
		}
	})
}

// TestPhaseHarnessProxy_SatisfiesTheHarnessSeam is a compile-time-ish guard that
// the proxy can stand in for the app wherever an agent takes appx.Harnesser.
func TestPhaseHarnessProxy_SatisfiesTheHarnessSeam(t *testing.T) {
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	proxy := NewPhaseHarnessProxy(o, "recon")
	if proxy == nil {
		t.Fatal("NewPhaseHarnessProxy returned nil")
	}
	// The assignment IS the assertion: it does not compile unless the proxy
	// implements appx.Harnesser.
	var seam appx.Harnesser = proxy
	_ = seam
}
