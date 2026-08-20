package phases

import (
	"context"
	"reflect"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/config"
)

// DefaultNodeID is the fallback in `os.getenv("NODE_ID", "cloudsecurity")`.
const DefaultNodeID = config.DefaultNodeID

// NodeID ports phases.py's module-level
//
//	NODE_ID = os.getenv("NODE_ID", "cloudsecurity")
//
// It delegates to config.NodeID so the prefix of every Call target this package
// builds is resolved by the SAME rule internal/node uses for the id the agent
// REGISTERS under. Python gets that invariant for free (one os.getenv spelling
// in all three modules); in Go it has to be a shared helper, because the two
// resolutions living apart is exactly how an exported-empty NODE_ID once
// produced a node registered as `cloudsecurity` that called ".run_iac_reader".
//
// Python parity caveat: Python evaluates that ONCE, at import time, so a later
// os.environ change is invisible to the running node. Go reads the environment
// at CALL time — a deliberate divergence that makes t.Setenv deterministic and
// that cannot change live behavior, because the node's NODE_ID is fixed before
// the first reasoner runs.
func NodeID() string { return config.NodeID() }

// The Python reasoner signatures' default arguments, named so the reasoner
// adapters (internal/reasoners) and the orchestrator cannot drift from them.
const (
	// DefaultDepth is `depth: str = "standard"` on every phase reasoner.
	DefaultDepth = "standard"
	// DefaultTier is `tier: int = 1` on recon_phase and prove_phase.
	DefaultTier = 1
	// DefaultMaxConcurrentHunters is `max_concurrent_hunters: int = 3` on
	// hunt_phase. NOTE it differs from BudgetConfig.max_concurrent_hunters
	// (4), which is what the orchestrator actually passes.
	DefaultMaxConcurrentHunters = 3
	// DefaultMaxChildren is `max_children: int = 3` on chain_phase.
	DefaultMaxChildren = 3
	// DefaultMaxConcurrentProvers is `max_concurrent_provers: int = 3` on
	// prove_phase.
	DefaultMaxConcurrentProvers = 3
	// DefaultMaxConcurrentRemediations is
	// `max_concurrent_remediations: int = 3` on remediation_phase.
	DefaultMaxConcurrentRemediations = 3
)

// chainLimitFallback / proverCapFallback are the literal second arguments of
// the two `.get(profile, N)` lookups in phases.py. They are unreachable — a
// _normalize_depth result is always a key of both tables — but they are part of
// the ported source, so they are named rather than inlined.
const (
	chainLimitFallback = 15
	proverCapFallback  = 30
)

// chainLimitFor ports `DEPTH_CHAIN_LIMITS.get(profile, 15)`.
func chainLimitFor(profile config.DepthProfile) int {
	if v, ok := config.DepthChainLimits[profile]; ok {
		return v
	}
	return chainLimitFallback
}

// proverCapFor ports `DEPTH_PROVER_CAPS.get(profile, 30)`.
func proverCapFor(profile config.DepthProfile) int {
	if v, ok := config.DepthProverCaps[profile]; ok {
		return v
	}
	return proverCapFallback
}

// callModel performs one `await router.call(f"{nodeID}.{reasoner}", **kwargs)`
// and materializes the reply the way phases.py does:
//
//	Model.model_validate(_as_dict(_unwrap(raw, name), name))
//
// `name` is the string phases.py passes to _unwrap/_as_dict, which is normally
// the reasoner name but deliberately NOT always (prove_phase passes the literal
// "prover"), so it is a separate parameter from the call target.
func callModel[T any](ctx context.Context, app appx.Caller, target, name string, kwargs map[string]any) (T, error) {
	var zero T
	raw, err := app.Call(ctx, target, kwargs)
	if err != nil {
		return zero, err
	}
	return bindCallResult[T](raw, name)
}

// bindCallResult is callModel's pure tail: unwrap the envelope, require a dict,
// bind the model. prove_phase needs it separately because it collects raw
// results from a gather() before unwrapping them.
func bindCallResult[T any](raw any, name string) (T, error) {
	var zero T
	payload, err := afx.UnwrapStrict(raw, name)
	if err != nil {
		return zero, err
	}
	m, err := afx.AsMap(payload, name)
	if err != nil {
		return zero, err
	}
	return afx.Bind[T](m)
}

// semaphore is asyncio.Semaphore(n): a buffered channel used as a counting
// semaphore. Capacity is clamped to at least 1 so a zero/negative limit cannot
// deadlock (every caller already computes max(1, ...), matching Python).
type semaphore chan struct{}

func newSemaphore(n int) semaphore {
	if n < 1 {
		n = 1
	}
	return make(semaphore, n)
}

func (s semaphore) acquire() { s <- struct{}{} }
func (s semaphore) release() { <-s }

// pyTruthy reproduces Python's bool(v) for the JSON value kinds that reach the
// providers scan (None, False, 0, "", [], {} are falsy).
//
// It is a local copy of the same predicate afx keeps unexported; duplicating
// six lines is preferable to widening afx's API for one call site.
func pyTruthy(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Bool:
		return rv.Bool()
	case reflect.String:
		return rv.Len() > 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() != 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() != 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() != 0
	case reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len() > 0
	case reflect.Pointer, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}
