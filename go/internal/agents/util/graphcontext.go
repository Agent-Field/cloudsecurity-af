package util

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// BuildGraphContextForHunter ports build_graph_context_for_hunter in
// src/cloudsecurity_af/agents/_utils.py.
//
// It reads the RECON phase's two artifacts — the resource graph and the
// resource inventory, both JSON files on disk — filters them down to one
// hunter's domain, and returns the three text blocks that hunter's prompt
// template interpolates:
//
//	nodeLines       -> {{RESOURCE_GRAPH_SUMMARY}}
//	inventoryStats  -> {{INVENTORY_STATS}}
//	edgeLines       -> {{RELEVANT_EDGES}}
//
// (Python returns them as the tuple (node_lines, inventory_stats, edge_lines),
// i.e. the STATS ARE IN THE MIDDLE while the prompt places them last. The
// hunters destructure it as
// `resource_graph_summary, inventory_stats, relevant_edges = ...`; the Go
// signature keeps the same order so the call sites read the same.)
//
// FILTERING. A node is "relevant" when its resource_type contains any of the
// lowercased domain keywords as a substring; an EMPTY keyword list (after
// dropping falsy entries — which is what the compliance hunter's `[""]`
// reduces to) matches EVERY node. An edge is relevant when either endpoint is
// a relevant node id. The non-relevant endpoints of relevant edges become the
// "1-hop neighbors" block.
//
// FAILURE IS SILENT. Python wraps each json.load in a bare `except Exception`
// and falls back to an empty document, then re-checks isinstance(dict). A
// missing, unreadable, malformed or non-object file therefore yields the
// "none matched this hunter domain" / "no edges matched this hunter domain"
// context rather than an error — which is why this function has no error
// return, and why the hunters keep running when RECON produced nothing.
//
// Python parity — LOWERCASING. Python's str.lower() applies full Unicode case
// mapping; Go's strings.ToLower is a per-rune simple mapping. The keyword
// tables are ASCII literals and Terraform resource types are ASCII, so the two
// agree on every input this port sees.
//
// Python parity — TYPE ERRORS. Python raises on a few shapes a hand-written
// graph file could hold (a non-string resource_type, a non-sized value under
// "nodes", an unhashable resource_id). Go renders them with str()/repr() and
// keeps going instead of failing the reasoner; each divergence is commented at
// its site in pyvalue.go. No file this port writes can reach them.
//
// DIVERGENCE — NEIGHBOR ORDER. See pyfmt.KeySet: Python iterates a
// `set` (hash order, randomized per process); Go emits first-encounter order.
func BuildGraphContextForHunter(graphPath, inventoryPath string, domainKeywords []string) (nodeLines, inventoryStats, edgeLines string) {
	graphData := loadObject(graphPath, defaultGraph())
	inventoryData := loadObject(inventoryPath, defaultInventory())

	// lowered_keywords = [k.lower() for k in domain_keywords if k]
	var loweredKeywords []string
	for _, keyword := range domainKeywords {
		if keyword == "" { // Python: `if keyword` — a falsy entry is dropped
			continue
		}
		loweredKeywords = append(loweredKeywords, strings.ToLower(keyword))
	}

	// def _matches(node_type): ...
	matches := func(nodeType any) bool {
		if len(loweredKeywords) == 0 {
			// Python parity: this returns BEFORE node_type.lower(), which is
			// why the compliance hunter's `[""]` never hits the string path.
			return true
		}
		lowered := strings.ToLower(pyfmt.Str(nodeType))
		for _, keyword := range loweredKeywords {
			if strings.Contains(lowered, keyword) {
				return true
			}
		}
		return false
	}

	rawNodes, _ := pyList(dictGetDefault(graphData, "nodes", []any{}))

	// all_nodes_by_id[node.get("resource_id", "")] = node  — note the "" default.
	allNodesByID := map[pyKey]pyfmt.Ordered{}
	for _, n := range rawNodes {
		if node, ok := pyDict(n); ok {
			allNodesByID[keyOf(dictGetDefault(node, "resource_id", ""))] = node
		}
	}

	// relevant_nodes / relevant_node_ids — note the MISSING default here, so a
	// node with no resource_id contributes Python None to the id set.
	var relevantNodes []pyfmt.Ordered
	relevantNodeIDs := newKeySet()
	for _, n := range rawNodes {
		node, ok := pyDict(n)
		if !ok || !matches(dictGetDefault(node, "resource_type", "")) {
			continue
		}
		relevantNodes = append(relevantNodes, node)
		relevantNodeIDs.Add(dictGet(node, "resource_id"))
	}

	rawEdges, _ := pyList(dictGetDefault(graphData, "edges", []any{}))

	var relevantEdges []pyfmt.Ordered
	for _, e := range rawEdges {
		edge, ok := pyDict(e)
		if !ok {
			continue
		}
		if relevantNodeIDs.Has(dictGet(edge, "source")) || relevantNodeIDs.Has(dictGet(edge, "target")) {
			relevantEdges = append(relevantEdges, edge)
		}
	}

	// neighbor_ids — note the "" default, which differs from the None default
	// used to build relevant_node_ids above. A malformed edge with no "source"
	// is therefore tested for membership as "" here and as None there.
	neighborIDs := newKeySet()
	for _, edge := range relevantEdges {
		source := dictGetDefault(edge, "source", "")
		target := dictGetDefault(edge, "target", "")
		if !relevantNodeIDs.Has(source) {
			neighborIDs.Add(source)
		}
		if !relevantNodeIDs.Has(target) {
			neighborIDs.Add(target)
		}
	}

	var neighborNodes []pyfmt.Ordered
	for _, id := range neighborIDs.Keys() {
		if node, ok := allNodesByID[id]; ok {
			neighborNodes = append(neighborNodes, node)
		}
	}

	// ---- node lines --------------------------------------------------------
	lines := []string{"RELEVANT RESOURCES:"}
	if len(relevantNodes) == 0 {
		lines = append(lines, "  - none matched this hunter domain")
	}
	for _, node := range relevantNodes {
		lines = append(lines, nodeHeadline(node), nodeConfigLine(node))
	}
	if len(neighborNodes) > 0 {
		// Python parity: the "\n" is INSIDE the appended element, so the
		// "\n".join below turns it into a blank separator line.
		lines = append(lines, "\nCONNECTED RESOURCES (1-hop neighbors):")
		for _, node := range neighborNodes {
			lines = append(lines, nodeHeadline(node), nodeConfigLine(node))
		}
	}

	// ---- edge lines --------------------------------------------------------
	edges := []string{"RELEVANT RELATIONSHIPS:"}
	if len(relevantEdges) == 0 {
		edges = append(edges, "  - no edges matched this hunter domain")
	}
	for _, edge := range relevantEdges {
		edges = append(edges, "  - "+pyfmt.Str(dictGet(edge, "source"))+
			" --["+pyfmt.Str(dictGetDefault(edge, "type", "references"))+"]--> "+
			pyfmt.Str(dictGet(edge, "target")))
		if description := dictGet(edge, "description"); pyTruthy(description) {
			edges = append(edges, "    "+pyfmt.Str(description))
		}
	}

	// ---- inventory stats ---------------------------------------------------
	rawResources, _ := pyList(dictGetDefault(inventoryData, "resources", []any{}))
	providers := providerList(rawResources)
	providersText := "none"
	if len(providers) > 0 {
		providersText = strings.Join(providers, ", ")
	}
	stats := strings.Join([]string{
		"Total resources: " + strconv.Itoa(pyLen(dictGetDefault(inventoryData, "resources", []any{}))),
		"Providers: " + providersText,
		"Modules: " + strconv.Itoa(pyLen(dictGetDefault(inventoryData, "modules", []any{}))),
		"Variables: " + strconv.Itoa(pyLen(dictGetDefault(inventoryData, "variables", []any{}))),
		"Outputs: " + strconv.Itoa(pyLen(dictGetDefault(inventoryData, "outputs", []any{}))),
		// Python parity: the graph counts come from the RAW documents, not
		// from the isinstance-filtered raw_nodes/raw_edges, so a graph whose
		// "nodes" is an object counts its KEYS here while contributing no
		// nodes above.
		"Graph nodes: " + strconv.Itoa(pyLen(dictGetDefault(graphData, "nodes", []any{}))),
		"Graph edges: " + strconv.Itoa(pyLen(dictGetDefault(graphData, "edges", []any{}))),
		"Filtered nodes: " + strconv.Itoa(len(relevantNodes)),
		"Filtered edges: " + strconv.Itoa(len(relevantEdges)),
	}, "\n")

	return strings.Join(lines, "\n"), stats, strings.Join(edges, "\n")
}

// nodeHeadline renders
// f"  - {node.get('resource_id')} ({node.get('resource_type')}) @ {node.get('file_path')}".
// The three lookups have NO default, so an absent key prints as "None".
func nodeHeadline(node pyfmt.Ordered) string {
	return "  - " + pyfmt.Str(dictGet(node, "resource_id")) +
		" (" + pyfmt.Str(dictGet(node, "resource_type")) + ")" +
		" @ " + pyfmt.Str(dictGet(node, "file_path"))
}

// nodeConfigLine renders f"    Config: {node.get('config_summary')}".
//
// config_summary is a DICT in every graph.json the RECON graph builder writes,
// so this is a CPython dict repr — `{'associate_public_ip_address': True}` —
// with the key order the .tf file had. pyfmt.Str is Python's str(), which for
// a container is repr(); pyfmt.Load kept the order in a pyfmt.Ordered.
func nodeConfigLine(node pyfmt.Ordered) string {
	return "    Config: " + pyfmt.Str(dictGet(node, "config_summary"))
}

// providerList ports
//
//	sorted({r.get("provider") for r in raw_resources if isinstance(r, dict) and r.get("provider")})
//
// i.e. the distinct TRUTHY provider values, sorted. Python's sorted() compares
// the values themselves and raises TypeError on a mixed-type set; Go dedupes on
// the Python-key identity and sorts the str() renderings, which is identical
// for the all-strings case every real inventory has.
func providerList(rawResources []any) []string {
	seen := newKeySet()
	var out []string
	for _, r := range rawResources {
		resource, ok := pyDict(r)
		if !ok {
			continue
		}
		provider := dictGet(resource, "provider")
		if !pyTruthy(provider) {
			continue
		}
		if seen.Has(provider) {
			continue
		}
		seen.Add(provider)
		out = append(out, pyfmt.Str(provider))
	}
	// sort.Strings compares bytes, which for UTF-8 is code-point order — the
	// same order Python's sorted() gives a set of str.
	sort.Strings(out)
	return out
}

// loadObject is the `try: json.load(open(path)) except Exception: default`
// plus the `if not isinstance(data, dict): data = default` re-check, in one
// step. Anything that is not a JSON object — including a valid JSON array,
// number or string — becomes the default.
func loadObject(path string, fallback pyfmt.Ordered) pyfmt.Ordered {
	data, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	value, err := pyfmt.Load(data)
	if err != nil {
		return fallback
	}
	obj, ok := pyDict(value)
	if !ok {
		return fallback
	}
	return obj
}

// defaultGraph is _default_graph.
func defaultGraph() pyfmt.Ordered {
	return pyfmt.Ordered{
		{K: "nodes", V: []any{}},
		{K: "edges", V: []any{}},
		{K: "clusters", V: []any{}},
	}
}

// defaultInventory is _default_inventory.
//
// Python parity: the last key is "provider_configs", which is NOT the key the
// real inventory writer emits ("providers"). It is dead either way — the stats
// block never reads it — but it is reproduced so the default document is the
// same object.
func defaultInventory() pyfmt.Ordered {
	return pyfmt.Ordered{
		{K: "resources", V: []any{}},
		{K: "modules", V: []any{}},
		{K: "variables", V: []any{}},
		{K: "outputs", V: []any{}},
		{K: "provider_configs", V: []any{}},
	}
}
