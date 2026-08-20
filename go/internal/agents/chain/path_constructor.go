package chain

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/prompts"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// pathConstructorPromptPath is PROMPT_PATH in path_constructor.py, resolved
// against the embedded prompt tree instead of the installed package's prompts/
// directory:
//
//	PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "chain" / "path_constructor.txt"
const pathConstructorPromptPath = "chain/path_constructor.txt"

// pathConstructorTempPrefix is the tempfile.mkdtemp prefix in
// run_path_constructor. Both the parent call and every child call use this one
// directory as their cwd.
const pathConstructorTempPrefix = "cloudsecurity-chain-"

// parentAgentName / childAgentName are the `agent_name` arguments Python passes
// to extract_harness_result; they appear verbatim in every error message and
// diagnostic line harnessx.Extract emits.
const (
	parentAgentName = "PathConstructor"
	childAgentName  = "PathConstructorChild"
)

// RunPathConstructor ports run_path_constructor in
// src/cloudsecurity_af/agents/chain/path_constructor.py:
//
//	started = time.perf_counter()
//	if not findings or max_paths <= 0 or max_children <= 0:
//	    return ChainResult(attack_paths=[], total_paths_evaluated=0,
//	                       viable_paths=0, chain_duration_seconds=0.0)
//	prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
//	parent_prompt = _build_parent_prompt(...)
//	harness_cwd = tempfile.mkdtemp(prefix="cloudsecurity-chain-")
//	try:
//	    plan_result = await app.harness(prompt=parent_prompt,
//	                                    schema=PathInvestigationPlan, cwd=harness_cwd)
//	    plan = extract_harness_result(plan_result, PathInvestigationPlan, "PathConstructor")
//	    investigations = plan.investigations[:max_children]
//	    if not investigations:
//	        return ChainResult(..., chain_duration_seconds=round(time.perf_counter()-started, 3))
//	    child_results = await asyncio.gather(*[_run_child(inv) for inv in investigations])
//	    viable_paths = [p for p in child_results if p is not None][:max_paths]
//	    return ChainResult(attack_paths=viable_paths,
//	                       total_paths_evaluated=len(investigations),
//	                       viable_paths=len(viable_paths),
//	                       chain_duration_seconds=round(time.perf_counter()-started, 3))
//	finally:
//	    shutil.rmtree(harness_cwd, ignore_errors=True)
//
// PYTHON PARITY — THE GUARD RETURNS A LITERAL 0.0. The `not findings or
// max_paths <= 0 or max_children <= 0` branch hard-codes
// chain_duration_seconds=0.0 rather than measuring; only the two later returns
// round the real elapsed time. That is reproduced exactly.
//
// PYTHON PARITY — NO project_dir. Unlike every prover and hunter call, the
// CHAIN harness calls pass only `cwd`; the model works from the JSON embedded
// in the prompt, not from the repository. harness.Options.ProjectDir is
// therefore left empty for both the parent and the children.
//
// That is SAFE for the concurrent children, and the reason is worth writing
// down because it is not obvious: the children all share one harnessCwd, and
// the SDK writes its schema output to a FIXED filename. The pinned SDK
// (sdk/go v0.1.131, harness/runner.go) resolves the output root as
// `ProjectDir or Cwd or "."` and then ALWAYS creates a per-run
// `.agentfield-out-*` directory under it whenever a schema is passed —
// harnessx.Run always passes one (harnessx.SchemaFor[T] never returns nil) —
// so each child gets its own output file and its own CleanupTempFiles target.
// The Python SDK does the same thing unconditionally
// (agentfield/harness/_runner.py: tempfile.mkdtemp(prefix=".agentfield-out-",
// dir=project_dir or resolved_cwd)). Adding ProjectDir here to "get isolation"
// would break the kwarg parity path_constructor_test.go pins without changing
// the root the model sees (every provider resolves `ProjectDir or Cwd`).
//
// PYTHON PARITY — CHILD FAILURES ARE SWALLOWED. `_run_child` wraps its harness
// call in `except Exception: return None`, so a child that errors, times out or
// returns an unparsable payload simply does not contribute a path — it never
// fails the phase. Only the parent call's failure propagates.
//
// CONCURRENCY. Python fans the children out with asyncio.gather and no
// semaphore, so up to max_children run at once and the phase waits for all of
// them. Go uses a WaitGroup writing into a pre-indexed slice, which preserves
// gather's ORDER guarantee: viable_paths is ordered by investigation index, not
// by completion. The handler ctx is passed through unchanged (it carries the
// execution context) but is never cancelled by this function: like gather, a
// failing child does not abort its siblings.
func RunPathConstructor(
	ctx context.Context,
	app appx.Harnesser,
	findings []schemas.RawFinding,
	resourceGraphPath string,
	maxPaths int,
	maxChildren int,
	driftReport *schemas.DriftReport,
) (schemas.ChainResult, error) {
	started := time.Now()

	if len(findings) == 0 || maxPaths <= 0 || maxChildren <= 0 {
		result := schemas.NewChainResult()
		result.ChainDurationSeconds = 0.0
		return result, nil
	}

	parentPrompt, err := BuildParentPrompt(findings, resourceGraphPath, driftReport, maxPaths, maxChildren)
	if err != nil {
		// Python parity: PROMPT_PATH.read_text() raising FileNotFoundError
		// surfaces as a failed reasoner, and it happens BEFORE mkdtemp.
		return schemas.ChainResult{}, err
	}

	harnessCwd, err := os.MkdirTemp("", pathConstructorTempPrefix)
	if err != nil {
		return schemas.ChainResult{}, fmt.Errorf("cloudsecurity chain: creating path-constructor work dir: %w", err)
	}
	// Python: `finally: shutil.rmtree(harness_cwd, ignore_errors=True)`.
	defer func() { _ = os.RemoveAll(harnessCwd) }() // ignore_errors=True

	plan, err := harnessx.RunExtract[schemas.PathInvestigationPlan](
		ctx, app, parentPrompt,
		harness.Options{Cwd: harnessCwd},
		parentAgentName,
	)
	if err != nil {
		return schemas.ChainResult{}, err
	}

	// Python: `plan.investigations[:max_children]` — a slice past the end is
	// the whole list, never an error.
	investigations := plan.Investigations
	if len(investigations) > maxChildren {
		investigations = investigations[:maxChildren]
	}
	if len(investigations) == 0 {
		result := schemas.NewChainResult()
		result.ChainDurationSeconds = pyfmt.Round(time.Since(started).Seconds(), 3)
		return result, nil
	}

	// Python: `await asyncio.gather(*[_run_child(inv) for inv in investigations])`.
	childResults := make([]*schemas.AttackPath, len(investigations))
	var wg sync.WaitGroup
	for i := range investigations {
		wg.Add(1)
		go func(idx int, inv schemas.ChildInvestigation) {
			defer wg.Done()
			path, err := harnessx.RunExtract[schemas.AttackPath](
				ctx, app, BuildChildPrompt(inv, maxPaths),
				harness.Options{Cwd: harnessCwd},
				childAgentName,
			)
			if err != nil {
				// Python: `except Exception: return None`.
				return
			}
			childResults[idx] = &path
		}(i, investigations[i])
	}
	wg.Wait()

	// Python: `[path for path in child_results if path is not None][:max_paths]`.
	viablePaths := make([]schemas.AttackPath, 0, len(childResults))
	for _, path := range childResults {
		if path != nil {
			viablePaths = append(viablePaths, *path)
		}
	}
	if len(viablePaths) > maxPaths {
		viablePaths = viablePaths[:maxPaths]
	}

	result := schemas.NewChainResult()
	result.AttackPaths = viablePaths
	result.TotalPathsEvaluated = len(investigations)
	// Python parity: viable_paths is counted AFTER the [:max_paths] truncation.
	result.ViablePaths = len(viablePaths)
	result.ChainDurationSeconds = pyfmt.Round(time.Since(started).Seconds(), 3)
	return result, nil
}

// BuildParentPrompt ports _build_parent_prompt. It is exported for the golden
// test, which compares it byte-for-byte against the string the Python builder
// emits.
//
//	prompt = template
//	prompt = prompt.replace("{{MAX_PATHS}}", str(max_paths))
//	prompt = prompt.replace("{{MAX_CHILDREN}}", str(max_children))
//	compact_findings = [_compact_finding(f) for f in findings]
//	prompt = prompt.replace("{{FINDINGS_JSON}}", json.dumps(compact_findings, indent=2))
//	try:    graph_data = json.load(open(resource_graph_path))
//	except: graph_data = {"nodes": [], "edges": [], "clusters": []}
//	if not isinstance(graph_data, dict): graph_data = {"nodes": [], "edges": [], "clusters": []}
//	prompt = prompt.replace("{{RESOURCE_GRAPH_JSON}}",
//	                        json.dumps(_filter_graph_for_findings(graph_data, findings), indent=2))
//	drift_payload = drift_report.model_dump() if drift_report is not None else {}
//	prompt = prompt.replace("{{DRIFT_REPORT_JSON}}", json.dumps(drift_payload, indent=2))
//
// PYTHON PARITY — SUBSTITUTION ORDER IS LOAD-BEARING. The four replacements run
// in sequence over the SAME string, so a placeholder that appears inside an
// earlier substitution's value is itself substituted. (A finding titled
// "{{DRIFT_REPORT_JSON}}" really does get the drift report spliced into it.)
// The Go port keeps the order rather than doing one pass.
//
// The only error this can return is a missing embedded template; every other
// failure mode Python has here (an unreadable or malformed graph file) is
// swallowed into the empty-graph default, exactly as the try/except does.
func BuildParentPrompt(
	findings []schemas.RawFinding,
	resourceGraphPath string,
	driftReport *schemas.DriftReport,
	maxPaths int,
	maxChildren int,
) (string, error) {
	template, err := prompts.Load(pathConstructorPromptPath)
	if err != nil {
		return "", err
	}

	prompt := template
	prompt = strings.ReplaceAll(prompt, "{{MAX_PATHS}}", strconv.Itoa(maxPaths))
	prompt = strings.ReplaceAll(prompt, "{{MAX_CHILDREN}}", strconv.Itoa(maxChildren))

	compactFindings := make([]any, 0, len(findings))
	for _, f := range findings {
		compactFindings = append(compactFindings, compactFinding(f))
	}
	prompt = strings.ReplaceAll(prompt, "{{FINDINGS_JSON}}", pyfmt.Dumps(compactFindings, 2))

	filtered := filterGraphForFindings(loadGraphData(resourceGraphPath), findings)
	prompt = strings.ReplaceAll(prompt, "{{RESOURCE_GRAPH_JSON}}", pyfmt.Dumps(filtered, 2))

	// Python: `drift_report.model_dump() if drift_report is not None else {}`.
	var driftPayload any = pyfmt.Ordered{}
	if driftReport != nil {
		driftPayload = *driftReport
	}
	prompt = strings.ReplaceAll(prompt, "{{DRIFT_REPORT_JSON}}", pyfmt.Dumps(driftPayload, 2))

	return prompt, nil
}

// BuildChildPrompt ports _child_prompt. Exported for the golden test.
//
//	return (
//	    f"{investigation.child_prompt.strip()}\n\n"
//	    "OUTPUT REQUIREMENTS:\n"
//	    "- Return a single JSON object matching AttackPath.\n"
//	    "- Only include a path if there is a coherent attacker progression across resources.\n"
//	    "- Use findings_involved IDs tied to the path steps.\n"
//	    "- Keep steps in strict step_number order starting at 1.\n"
//	    f"- The parent will keep at most {max_paths} final attack paths."
//	)
func BuildChildPrompt(investigation schemas.ChildInvestigation, maxPaths int) string {
	return pyStrip(investigation.ChildPrompt) + "\n\n" +
		"OUTPUT REQUIREMENTS:\n" +
		"- Return a single JSON object matching AttackPath.\n" +
		"- Only include a path if there is a coherent attacker progression across resources.\n" +
		"- Use findings_involved IDs tied to the path steps.\n" +
		"- Keep steps in strict step_number order starting at 1.\n" +
		"- The parent will keep at most " + strconv.Itoa(maxPaths) + " final attack paths."
}

// compactFinding ports _compact_finding: the 8-key projection of a RawFinding
// that goes into {{FINDINGS_JSON}}.
//
//	{"id", "title", "category", "severity", "resources", "iac_file", "iac_line",
//	 "fingerprint"}
//
// Python parity: the key order below is the dict-literal order, which json.dumps
// preserves, so it is part of the prompt bytes.
//
// Python parity: `severity` is
// `f.estimated_severity.value if hasattr(f.estimated_severity, "value") else str(...)`.
// pydantic always yields the enum, so the branch is always `.value` — the Go
// Severity is already that string.
//
// Python parity: `resources` is `[r.resource_id for r in f.resources] if f.resources else []`,
// i.e. an empty list either way; a nil Go slice must still render as `[]`.
func compactFinding(f schemas.RawFinding) pyfmt.Ordered {
	resources := make([]any, 0, len(f.Resources))
	for _, r := range f.Resources {
		resources = append(resources, r.ResourceID)
	}
	return pyfmt.Ordered{
		{K: "id", V: f.ID},
		{K: "title", V: f.Title},
		{K: "category", V: f.Category},
		{K: "severity", V: f.EstimatedSeverity.String()},
		{K: "resources", V: resources},
		{K: "iac_file", V: f.IaCFile},
		{K: "iac_line", V: f.IaCLine},
		{K: "fingerprint", V: f.Fingerprint},
	}
}

// emptyGraph is the `{"nodes": [], "edges": [], "clusters": []}` literal
// _build_parent_prompt falls back to when the graph file cannot be read or is
// not a JSON object.
func emptyGraph() pyfmt.Ordered {
	return pyfmt.Ordered{
		{K: "nodes", V: []any{}},
		{K: "edges", V: []any{}},
		{K: "clusters", V: []any{}},
	}
}

// loadGraphData ports the graph-file read inside _build_parent_prompt: any
// failure (missing file, permissions, malformed JSON) and any non-object
// top-level value collapse to the empty-graph default.
//
// The decode is order-preserving (pyfmt.Load) because the filtered nodes and
// edges are re-emitted verbatim into the prompt, and a Python dict would have
// kept the file's key order.
func loadGraphData(resourceGraphPath string) pyfmt.Ordered {
	data, err := os.ReadFile(resourceGraphPath)
	if err != nil {
		return emptyGraph()
	}
	loaded, err := pyfmt.Load(data)
	if err != nil {
		return emptyGraph()
	}
	obj, ok := loaded.(pyfmt.Ordered)
	if !ok {
		// Python: `if not isinstance(graph_data, dict)`.
		return emptyGraph()
	}
	return obj
}

// filterGraphForFindings ports _filter_graph_for_findings: reduce the resource
// graph to the nodes the findings touch plus their 1-hop neighbours, and to the
// edges whose BOTH endpoints survive.
//
//	finding_resources = {r.resource_id for f in findings for r in f.resources} | {f.iac_file if f.iac_file}
//	neighbors = {other end of any edge with one end in finding_resources}
//	relevant_ids = finding_resources | neighbors
//	nodes = [n for n in graph["nodes"] if n.get("resource_id") in relevant_ids]
//	edges = [e for e in graph["edges"] if e.get("source") in relevant_ids and e.get("target") in relevant_ids]
//	return {"nodes": nodes, "edges": edges, "clusters": graph.get("clusters", [])}
//
// PYTHON PARITY — TWO DIFFERENT `.get` DEFAULTS. The neighbour pass reads
// `edge.get("source", "")` (a missing key becomes the empty string, which DOES
// match when some finding has an empty resource_id) while the edge filter reads
// `edge.get("source")` (a missing key becomes None, which matches only if some
// edge already put None in the id set). Both are reproduced.
//
// PYTHON PARITY — `clusters` IS PASSED THROUGH UNTOUCHED, whatever its type,
// including when it is absent (then `[]`).
//
// PYTHON PARITY — IDS ARE COMPARED BY VALUE, NOT AS STRINGS. `relevant_ids` is
// a plain Python set, so a non-string endpoint (JSON null, a number, a bool)
// joins it and then MATCHES in the node and edge filters. The neighbour pass
//
//	src, tgt = edge.get("source", ""), edge.get("target", "")
//	if src in finding_resources: neighbors.add(tgt)
//
// adds the OTHER endpoint unconditionally, without inspecting its type. That is
// reachable: graph.json is written by the deterministic graphfast builder on the
// happy path (always string ids), but resource_graph_builder falls back to the
// harness on error and prompts/recon/resource_graph_builder.txt tells the model
// to author graph.json itself. Verified against the repo venv with
//
//	graph    {"nodes":[{"resource_id":"a","resource_type":"t"},
//	                   {"resource_id":null,"resource_type":"nullid"}],
//	          "edges":[{"source":"a","target":null,"type":"e1"},
//	                   {"source":null,"target":"a","type":"e2"}],
//	          "clusters":[]}
//	finding  resources=[AffectedResource(resource_id="a")]
//
// -> BOTH nodes and BOTH edges survive. pyfmt.KeySet supplies the by-value
// membership (and documents the two divergences it keeps: iteration order,
// which this function never observes, and unhashable list/dict ids, which
// Python rejects with TypeError).
//
// Reproducing that must NOT be done by collapsing a non-string endpoint onto
// "", which is a MEMBER of the id set whenever some finding carries an empty
// resource_id (`resource_id: str` has no min_length, so a model can and does
// emit ""). Verified against the venv with
// edges=[{"source": 5, "target": "aws_s3_bucket.logs"}] and one finding whose
// resource_id is "": Python filters everything out, while collapsing `5` to ""
// splices aws_s3_bucket.logs into {{RESOURCE_GRAPH_JSON}} — a prompt byte
// difference. endpointOrEmpty keeps "absent" and "present but not a str" apart.
func filterGraphForFindings(graphData pyfmt.Ordered, findings []schemas.RawFinding) pyfmt.Ordered {
	// finding_resources is a set of Python strs — RawFinding.resources[].resource_id
	// and RawFinding.iac_file are both `str` in pydantic.
	findingResources := pyfmt.NewKeySet()
	for _, f := range findings {
		for _, r := range f.Resources {
			findingResources.Add(r.ResourceID)
		}
		if f.IaCFile != "" {
			findingResources.Add(f.IaCFile)
		}
	}

	rawEdges := listField(graphData, "edges")

	// relevant_ids = finding_resources | neighbors — a NEW set, so the
	// neighbour additions below must not leak back into finding_resources.
	relevantIDs := findingResources.Clone()
	for _, edge := range rawEdges {
		edgeObj, ok := edge.(pyfmt.Ordered)
		if !ok {
			// Python: `if not isinstance(edge, dict): continue`.
			continue
		}
		// Python: `src, tgt = edge.get("source", ""), edge.get("target", "")`,
		// then each membership hit adds the OPPOSITE endpoint's raw value.
		src := endpointOrEmpty(edgeObj, "source")
		tgt := endpointOrEmpty(edgeObj, "target")
		if findingResources.Has(src) {
			relevantIDs.Add(tgt)
		}
		if findingResources.Has(tgt) {
			relevantIDs.Add(src)
		}
	}

	rawNodes := listField(graphData, "nodes")
	filteredNodes := make([]any, 0, len(rawNodes))
	for _, node := range rawNodes {
		nodeObj, ok := node.(pyfmt.Ordered)
		if !ok {
			continue
		}
		// Python: `n.get("resource_id") in relevant_ids` — no default, so a
		// missing key is None, which matches only if None is in the set.
		if relevantIDs.Has(dictGet(nodeObj, "resource_id")) {
			filteredNodes = append(filteredNodes, node)
		}
	}

	filteredEdges := make([]any, 0, len(rawEdges))
	for _, edge := range rawEdges {
		edgeObj, ok := edge.(pyfmt.Ordered)
		if !ok {
			continue
		}
		if relevantIDs.Has(dictGet(edgeObj, "source")) && relevantIDs.Has(dictGet(edgeObj, "target")) {
			filteredEdges = append(filteredEdges, edge)
		}
	}

	clusters, ok := graphData.Get("clusters")
	if !ok {
		clusters = []any{}
	}

	return pyfmt.Ordered{
		{K: "nodes", V: filteredNodes},
		{K: "edges", V: filteredEdges},
		{K: "clusters", V: clusters},
	}
}

// listField ports `x = graph_data.get(key, []); if not isinstance(x, list): x = []`.
func listField(obj pyfmt.Ordered, key string) []any {
	v, ok := obj.Get(key)
	if !ok {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	return list
}

// dictGet is `d.get(key)` with NO default: an absent key yields Python None,
// which is a distinct set key from "" and from the string "None".
func dictGet(obj pyfmt.Ordered, key string) any {
	v, ok := obj.Get(key)
	if !ok {
		return nil
	}
	return v
}

// endpointOrEmpty is the neighbour pass's `edge.get(key, "")`. The default is
// substituted ONLY for an absent key; a present non-string value (5, null, a
// list) is returned as-is, because Python compares it by value rather than
// coercing it. The two cases behave differently: "" IS a member of the id set
// whenever a finding carries an empty resource_id, while 5 and None are members
// only if the graph itself put them there.
func endpointOrEmpty(obj pyfmt.Ordered, key string) any {
	v, ok := obj.Get(key)
	if !ok {
		return ""
	}
	return v
}

// pyStrip reproduces Python's str.strip() with no argument, which trims every
// character whose Py_UNICODE_ISSPACE is true.
//
// That set is Go's unicode.IsSpace PLUS U+001C..U+001F (the FILE, GROUP, RECORD
// and UNIT separators), which Python counts as whitespace and Go does not. The
// child prompt is model-authored free text, so the difference is reachable in
// principle; handling it costs one predicate.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
	})
}
