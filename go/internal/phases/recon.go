package phases

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"sync"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// ReconPhase ports src/cloudsecurity_af/reasoners/phases.py recon_phase.
//
// Python:
//
//	@router.reasoner()
//	async def recon_phase(repo_path: str, depth: str = "standard", tier: int = 1,
//	                      cloud_config: dict[str, Any] | None = None) -> dict[str, Any]:
//
// DAG shape:
//
//	recon_phase
//	├── run_iac_reader                          (sequential)
//	├── run_resource_graph_builder              (sequential, needs the inventory path)
//	├── run_cloud_connector  ┐ gather(2) — only when tier >= 2 AND cloud_config is not None
//	└── run_drift_detector   ┘
//
// Python parity notes:
//
//   - `depth` is accepted and IGNORED. recon_phase never reads it; it exists
//     only so the orchestrator can pass the same kwarg to every phase. Keep the
//     parameter — dropping it would change the reasoner's input schema.
//   - The tier-2 gate is `tier >= 2 and cloud_config is not None`. A nil Go map
//     is None; an EMPTY but non-nil map is `{}`, which is not None, so it opens
//     the gate exactly as Python's `{} is not None` does.
//   - asyncio.gather propagates whichever of the two calls fails FIRST in wall
//     clock time, and Python then unwraps the two replies SEQUENTIALLY
//     (connector, then detector) after the gather returns. Go unwraps inside
//     each goroutine and reports the cloud-connector slot before the drift
//     slot. That matches Python for the common cases (only one side fails; both
//     sides fail on their envelope) and is a deliberate determinism fix for the
//     rest. Neither implementation cancels the sibling call — asyncio.gather
//     does not either, so ctx is passed through untouched.
//   - providers_detected is read back off the inventory FILE, not off the
//     ResourceInventory model, and ANY failure yields an empty list.
func ReconPhase(
	ctx context.Context,
	app appx.Caller,
	nodeID string,
	repoPath string,
	depth string,
	tier int,
	cloudConfig map[string]any,
) (afx.Payload, error) {
	_ = depth // Python parity: recon_phase declares `depth` but never reads it.

	inventory, err := callModel[schemas.ResourceInventory](ctx, app,
		nodeID+".run_iac_reader", "run_iac_reader",
		map[string]any{
			"repo_path": repoPath,
		})
	if err != nil {
		return nil, err
	}

	resourceGraph, err := callModel[schemas.ResourceGraph](ctx, app,
		nodeID+".run_resource_graph_builder", "run_resource_graph_builder",
		map[string]any{
			"repo_path":      repoPath,
			"inventory_path": inventory.InventorySavedPath,
		})
	if err != nil {
		return nil, err
	}

	var driftReport *schemas.DriftReport
	var liveInventory *schemas.ResourceInventory

	if tier >= 2 && cloudConfig != nil {
		var (
			wg        sync.WaitGroup
			live      schemas.ResourceInventory
			liveErr   error
			drift     schemas.DriftReport
			driftErr  error
			connector = nodeID + ".run_cloud_connector"
			detector  = nodeID + ".run_drift_detector"
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			live, liveErr = callModel[schemas.ResourceInventory](ctx, app,
				connector, "run_cloud_connector",
				map[string]any{
					"cloud_config": cloudConfig,
				})
		}()
		go func() {
			defer wg.Done()
			drift, driftErr = callModel[schemas.DriftReport](ctx, app,
				detector, "run_drift_detector",
				map[string]any{
					"iac_graph_path": resourceGraph.GraphSavedPath,
					"cloud_config":   cloudConfig,
				})
		}()
		wg.Wait()

		if liveErr != nil {
			return nil, liveErr
		}
		if driftErr != nil {
			return nil, driftErr
		}
		liveInventory = &live
		driftReport = &drift
	}

	recon := schemas.NewReconResult()
	recon.Inventory = inventory
	recon.ResourceGraph = resourceGraph
	recon.DriftReport = driftReport
	recon.LiveInventory = liveInventory
	recon.IaCType = inventory.IaCType
	recon.ProvidersDetected = providersFromInventoryFile(inventory.InventorySavedPath)
	recon.TotalResources = inventory.TotalResources
	recon.TotalEdges = resourceGraph.TotalEdges

	// Python: `return recon.model_dump()` — afx.Dump keeps pydantic's field
	// declaration order, which json.dumps preserves on the wire.
	return afx.Dump(recon)
}

// providersFromInventoryFile ports the inline block at the end of recon_phase:
//
//	try:
//	    with open(inventory.inventory_saved_path, "r") as f:
//	        inv_data = json.load(f)
//	        if not isinstance(inv_data, dict): inv_data = {"resources": []}
//	        raw_res = inv_data.get("resources", [])
//	        if not isinstance(raw_res, list): raw_res = []
//	        providers = sorted({r.get("provider") for r in raw_res
//	                            if isinstance(r, dict) and r.get("provider")})
//	except Exception:
//	    providers = []
//
// i.e. the distinct truthy `provider` strings of the inventory's resources, in
// sorted order — with a missing file, malformed JSON or any other failure
// collapsing to an empty list rather than an error.
//
// sorted() over a set of str sorts by code point; Go's sort.Strings sorts by
// byte, and for UTF-8 the two orders coincide.
//
// DIVERGENCE (unreachable in practice): if a resource carries a NON-string
// truthy provider, Python's sorted() raises a TypeError only when the set is
// mixed-type — an all-int set would sort, and then pydantic would reject the
// list[str] field. Go has nowhere to put a non-string, so it takes the
// documented "any failure -> []" branch. The inventory writer
// (agents/recon/tfparse.go) only ever emits provider strings.
func providersFromInventoryFile(path string) []string {
	empty := []string{}

	data, err := os.ReadFile(path)
	if err != nil {
		return empty
	}
	var top any
	if err := json.Unmarshal(data, &top); err != nil {
		return empty
	}

	invData, isObject := top.(map[string]any)
	if !isObject {
		// Python parity: a non-dict document is replaced wholesale by
		// {"resources": []}, so there is nothing left to scan.
		return empty
	}
	rawRes, present := invData["resources"]
	if !present {
		return empty
	}
	list, isList := rawRes.([]any)
	if !isList {
		return empty
	}

	seen := make(map[string]struct{}, len(list))
	for _, element := range list {
		resource, isDict := element.(map[string]any)
		if !isDict {
			continue
		}
		provider, has := resource["provider"]
		if !has || !pyTruthy(provider) {
			continue
		}
		name, isString := provider.(string)
		if !isString {
			return empty
		}
		seen[name] = struct{}{}
	}

	providers := make([]string, 0, len(seen))
	for name := range seen {
		providers = append(providers, name)
	}
	sort.Strings(providers)
	return providers
}
