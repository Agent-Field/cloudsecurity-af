package phases

import (
	"context"
	"strconv"
	"sync"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/config"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// severityRank ports the sev_rank dict that phases.py builds twice (once in
// _cross_hunter_dedup, once in _prioritize_findings) with identical contents:
//
//	{CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1}
//
// Both call sites read it with `.get(severity, 0)`, so an unknown severity
// ranks 0 — below INFO.
var severityRank = map[scoring.Severity]int{
	scoring.SeverityCritical: 5,
	scoring.SeverityHigh:     4,
	scoring.SeverityMedium:   3,
	scoring.SeverityLow:      2,
	scoring.SeverityInfo:     1,
}

// HuntPhase ports src/cloudsecurity_af/reasoners/phases.py hunt_phase.
//
// Python:
//
//	@router.reasoner()
//	async def hunt_phase(repo_path: str, resource_graph_path: str, inventory_path: str,
//	                     depth: str = "standard", max_concurrent_hunters: int = 3) -> dict[str, Any]:
//
// DAG shape: one `run_<hunter>_hunter` child per entry of DEPTH_HUNTER_MAP for
// the normalized depth (5 for quick, 7 for standard/thorough), fanned out under
// a semaphore of max(1, min(max_concurrent_hunters, len(active_hunters))).
//
// Python parity notes:
//
//   - A hunter that fails — transport error, strict-unwrap failure or a payload
//     that will not bind — contributes an EMPTY batch and NOTHING else. Python
//     catches the exception and never notes it (`except Exception as exc:` with
//     `exc` unused); the port must not add a note either.
//   - The producer/consumer split is real, not decorative: an asyncio.Queue
//     feeds a consumer coroutine that dedups by fingerprint AS BATCHES ARRIVE,
//     so total_raw counts every finding the hunters produced while `findings`
//     holds only the first occurrence of each fingerprint. The Go port keeps
//     the same shape with a buffered channel plus a consumer goroutine.
//   - Batch arrival order is COMPLETION order, in Go as in Python. Which of two
//     same-fingerprint findings survives, and the order of the surviving list,
//     therefore depends on hunter timing in both implementations. (The
//     downstream consumers — chain_phase's max_paths, prove_phase's severity
//     sort — do not depend on it.)
//   - A finding with an empty fingerprint is assigned
//     f"{iac_file}:{iac_line}:{category}" and MUTATED in place, so the
//     synthesized fingerprint travels on into the HuntResult.
//   - hunt_duration_seconds is hard-coded to 0.0 here; the orchestrator
//     overwrites it after the call returns.
func HuntPhase(
	ctx context.Context,
	app appx.Caller,
	nodeID string,
	repoPath string,
	resourceGraphPath string,
	inventoryPath string,
	depth string,
	maxConcurrentHunters int,
) (afx.Payload, error) {
	profile := config.NormalizeDepth(depth)
	activeHunters := config.HuntersForDepth(profile)

	concurrencyLimit := maxConcurrentHunters
	if len(activeHunters) < concurrencyLimit {
		concurrencyLimit = len(activeHunters)
	}
	if concurrencyLimit < 1 {
		concurrencyLimit = 1
	}
	sem := newSemaphore(concurrencyLimit)

	// asyncio.Queue() is unbounded; a channel sized to the producer count can
	// never block a producer either, which is what keeps the semaphore's hold
	// time identical to Python's (`async with semaphore:` wraps the put).
	batches := make(chan []schemas.RawFinding, len(activeHunters))

	var wg sync.WaitGroup
	for _, hunter := range activeHunters {
		wg.Add(1)
		go func(hunterName string) {
			defer wg.Done()
			sem.acquire()
			defer sem.release()

			operationName := "run_" + hunterName + "_hunter"
			payload, err := callModel[schemas.HuntResult](ctx, app,
				nodeID+"."+operationName, operationName,
				map[string]any{
					"repo_path":           repoPath,
					"resource_graph_path": resourceGraphPath,
					"inventory_path":      inventoryPath,
					"depth":               depth,
				})
			if err != nil {
				// Python parity: `except Exception: await queue.put([])` —
				// silent, no note, no error propagation.
				batches <- []schemas.RawFinding{}
				return
			}
			batches <- payload.Findings
		}(hunter)
	}

	type dedupResult struct {
		findings []schemas.RawFinding
		totalRaw int
	}
	consumed := make(chan dedupResult, 1)
	go func() {
		allFindings := make([]schemas.RawFinding, 0)
		seenFingerprints := make(map[string]struct{})
		totalRaw := 0

		for completed := 0; completed < len(activeHunters); completed++ {
			batch := <-batches
			totalRaw += len(batch)
			for _, finding := range batch {
				fingerprint := finding.Fingerprint
				if fingerprint == "" {
					fingerprint = synthesizeFingerprint(finding)
					finding.Fingerprint = fingerprint
				}
				if _, dup := seenFingerprints[fingerprint]; dup {
					continue
				}
				seenFingerprints[fingerprint] = struct{}{}
				allFindings = append(allFindings, finding)
			}
		}
		consumed <- dedupResult{findings: crossHunterDedup(allFindings), totalRaw: totalRaw}
	}()

	wg.Wait()
	result := <-consumed

	hunt := schemas.NewHuntResult()
	hunt.Findings = result.findings
	hunt.TotalRaw = result.totalRaw
	hunt.DeduplicatedCount = len(result.findings)
	hunt.StrategiesRun = activeHunters
	// Python parity: hunt_duration_seconds=0.0 — the phase does not time itself.
	hunt.HuntDurationSeconds = 0.0

	// Python: `return hunt_result.model_dump()`.
	return afx.Dump(hunt)
}

// synthesizeFingerprint ports
// `fp = f"{finding.iac_file}:{finding.iac_line}:{finding.category}"`.
func synthesizeFingerprint(finding schemas.RawFinding) string {
	return finding.IaCFile + ":" + strconv.Itoa(finding.IaCLine) + ":" + finding.Category
}

// crossHunterDedup ports phases.py _cross_hunter_dedup: collapse findings that
// name the same primary resource AND the same category, keeping the
// highest-severity one.
//
//	primary_resource = f.resources[0].resource_id if f.resources else f.iac_file
//	dedup_key = f"{primary_resource}::{f.category}"
//
// Python parity: the winner REPLACES the loser at the loser's position, because
// `seen[dedup_key] = f` rewrites an existing dict entry in place and
// `list(seen.values())` walks insertion order. The Go port keeps an explicit
// key order slice to reproduce that; ranging a Go map would be randomized.
//
// Python parity: the replacement test is STRICTLY greater, so the FIRST finding
// at the top severity for a key wins ties.
func crossHunterDedup(findings []schemas.RawFinding) []schemas.RawFinding {
	seen := make(map[string]schemas.RawFinding, len(findings))
	order := make([]string, 0, len(findings))

	for _, finding := range findings {
		primaryResource := finding.IaCFile
		if len(finding.Resources) > 0 {
			primaryResource = finding.Resources[0].ResourceID
		}
		dedupKey := primaryResource + "::" + finding.Category

		existing, present := seen[dedupKey]
		if !present {
			seen[dedupKey] = finding
			order = append(order, dedupKey)
			continue
		}
		if severityRank[finding.EstimatedSeverity] > severityRank[existing.EstimatedSeverity] {
			seen[dedupKey] = finding
		}
	}

	out := make([]schemas.RawFinding, 0, len(order))
	for _, key := range order {
		out = append(out, seen[key])
	}
	return out
}
