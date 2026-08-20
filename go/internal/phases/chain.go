package phases

import (
	"context"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/config"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// ChainPhase ports src/cloudsecurity_af/reasoners/phases.py chain_phase.
//
// Python:
//
//	@router.reasoner()
//	async def chain_phase(findings: list[dict[str, Any]], resource_graph_path: str,
//	                      drift_report: dict[str, Any] | None = None,
//	                      depth: str = "standard", max_children: int = 3) -> dict[str, Any]:
//
// DAG shape: exactly ONE child, run_path_constructor. The fan-out that the
// CHAIN phase is famous for happens INSIDE the path constructor (meta-prompting
// over max_children child investigations), not here.
//
// Python parity notes:
//
//   - `findings` and `drift_report` are forwarded VERBATIM — chain_phase never
//     binds them to a model, so a malformed finding reaches
//     run_path_constructor unchanged and the CHILD is what fails
//     (RawFinding.model_validate inside the path constructor), producing a
//     failed child execution in the DAG and the relayed
//     "run_path_constructor failed: ..." error. `findings` is therefore
//     `[]any`, not `[]map[string]any`: a non-object element must survive this
//     hop, exactly as it does in Python, instead of failing the parent's bind.
//     `drift_report` stays a raw map for the same reason.
//   - max_paths comes from DEPTH_CHAIN_LIMITS (quick 5, standard 15,
//     thorough 100), NOT from a parameter.
//   - drift_report is passed even when nil, so `drift_report` is always a key
//     of the child's input (value null). Dropping the key would change the
//     child reasoner's binding.
func ChainPhase(
	ctx context.Context,
	app appx.Caller,
	nodeID string,
	findings []any,
	resourceGraphPath string,
	driftReport map[string]any,
	depth string,
	maxChildren int,
) (afx.Payload, error) {
	profile := config.NormalizeDepth(depth)
	maxPaths := chainLimitFor(profile)

	// A nil Go map must reach the child as JSON null, not as {}. Boxing it in
	// an `any` keeps encoding/json's nil-map-to-null rule; the explicit nil
	// keeps the intent obvious.
	var driftArg any
	if driftReport != nil {
		driftArg = driftReport
	}
	// Python types `findings` as a required list, so it is never None. A nil
	// Go slice would marshal to null, which the child would bind as an empty
	// list anyway; normalizing keeps the emitted kwargs shape honest.
	var findingsArg any = findings
	if findings == nil {
		findingsArg = []any{}
	}

	chain, err := callModel[schemas.ChainResult](ctx, app,
		nodeID+".run_path_constructor", "run_path_constructor",
		map[string]any{
			"findings":            findingsArg,
			"resource_graph_path": resourceGraphPath,
			"max_paths":           maxPaths,
			"max_children":        maxChildren,
			"drift_report":        driftArg,
		})
	if err != nil {
		return nil, err
	}

	// Python: `return chain_result.model_dump()`.
	return afx.Dump(chain)
}
