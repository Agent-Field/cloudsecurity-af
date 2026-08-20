package recon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// This file ports src/cloudsecurity_af/agents/recon/_graph_builder_fast.py —
// the deterministic ResourceGraph builder that reads inventory.json and writes
// graph.json without ever calling the harness.

// edgeTypeRule is one entry of Python's _EDGE_TYPE_MAP.
type edgeTypeRule struct {
	Keyword string
	Type    string
}

// edgeTypeMap is _EDGE_TYPE_MAP.
//
// ORDER IS LOAD-BEARING: _infer_edge_type returns the FIRST entry whose keyword
// appears in either type, and Python iterates a dict in insertion order. A Go
// map would be iterated in randomized order and pick a different edge type run
// to run, so this is a slice in the exact source order of the Python literal.
var edgeTypeMap = []edgeTypeRule{
	{"iam", "trust"},
	{"role", "trust"},
	{"policy", "trust"},
	{"assume", "trust"},
	{"subnet", "network_path"},
	{"security_group", "network_path"},
	{"route", "network_path"},
	{"vpc", "network_path"},
	{"lb", "network_path"},
	{"elb", "network_path"},
	{"alb", "network_path"},
	{"nlb", "network_path"},
	{"gateway", "network_path"},
	{"igw", "network_path"},
	{"nat", "network_path"},
	{"nacl", "network_path"},
	{"network_interface", "network_path"},
	{"peering", "network_path"},
	{"endpoint", "network_path"},
	{"flow_log", "network_path"},
	{"bucket", "data_access"},
	{"dynamodb", "data_access"},
	{"rds", "data_access"},
	{"db_instance", "data_access"},
	{"db_subnet", "data_access"},
	{"db_option", "data_access"},
	{"db_parameter", "data_access"},
	{"s3", "data_access"},
	{"kms", "data_access"},
	{"sqs", "data_access"},
	{"sns", "data_access"},
	{"neptune", "data_access"},
	{"elasticsearch", "data_access"},
	{"es_domain", "data_access"},
	{"redshift", "data_access"},
	{"ebs", "data_access"},
	{"efs", "data_access"},
	{"backup", "data_access"},
	{"snapshot", "data_access"},
	{"lambda", "execution"},
	{"function", "execution"},
	{"instance", "execution"},
	{"ecs", "execution"},
	{"eks", "execution"},
	{"ecr", "execution"},
	{"task", "execution"},
	{"fargate", "execution"},
	{"node_group", "execution"},
	{"launch_template", "execution"},
	{"auto_scaling", "execution"},
}

// inferEdgeType ports _infer_edge_type.
//
// Python parity: callers pass a resource ID where the parameter is named
// "type" (`_infer_edge_type(source_type, ref)`), which is intentional — the
// substring test works on both.
func inferEdgeType(sourceType, targetType string) string {
	for _, rule := range edgeTypeMap {
		if strings.Contains(sourceType, rule.Keyword) || strings.Contains(targetType, rule.Keyword) {
			return rule.Type
		}
	}
	return "references"
}

// networkClusterKeywords / identityClusterKeywords / dataClusterKeywords /
// computeClusterKeywords are the four keyword tuples of _cluster_key, in source
// order (irrelevant to the result — the test is `any(...)` — but kept so the
// tables diff cleanly against the Python).
var (
	networkClusterKeywords = []string{
		"vpc", "subnet", "security_group", "route", "gateway", "igw", "nat", "nacl",
		"elb", "alb", "nlb", "lb", "network_interface", "peering", "endpoint", "flow_log",
	}
	identityClusterKeywords = []string{"iam", "role", "policy", "user", "group", "access_key"}
	dataClusterKeywords     = []string{
		"s3", "bucket", "rds", "db_instance", "dynamodb", "neptune", "elasticsearch",
		"redshift", "ebs", "efs", "kms", "snapshot", "backup",
	}
	computeClusterKeywords = []string{"lambda", "function", "instance", "ecs", "eks", "ecr", "fargate"}
)

// configSummaryKeywords is the keyword tuple of the `security_attrs` dict
// comprehension in build_graph_from_inventory.
var configSummaryKeywords = []string{
	"encrypt", "public", "acl", "policy", "logging", "ssl", "tls", "secret",
	"password", "key", "auth", "cidr", "ingress", "egress", "port", "protocol", "versioning",
}

func containsAny(haystack string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(haystack, kw) {
			return true
		}
	}
	return false
}

// clusterKey ports _cluster_key.
//
// Python parity — THIS FUNCTION IS WHERE A MALFORMED INVENTORY BLOWS UP, and
// blowing up is load-bearing: run_resource_graph_builder wraps the whole fast
// path in `except Exception` and falls back to the LLM harness, so a raise here
// is what makes a bad inventory.json produce a REAL graph instead of a silently
// edge-less one.
//
//	parts = file_path.split("/")   -> AttributeError when file_path is not a str
//	any(kw in rtype for kw in ...) -> TypeError when rtype is not a str
//
// The order matters and is reproduced: `file_path.split` runs before the rtype
// membership tests, so a resource with both fields malformed raises the
// AttributeError. Verified against the repo venv.
func clusterKey(resource pyfmt.Ordered) (string, error) {
	// Python: `file_path.split("/")`.
	filePath, badType := invStr(resource, "file_path")
	if badType != "" {
		return "", fmt.Errorf("'%s' object has no attribute 'split'", badType)
	}
	// Python: `kw in rtype`, whose TypeError message names the ARGUMENT type.
	rtype, badType := invStr(resource, "type")
	if badType != "" {
		return "", fmt.Errorf("argument of type '%s' is not iterable", badType)
	}

	parts := strings.Split(filePath, "/")
	moduleDir := "root"
	if len(parts) > 1 {
		moduleDir = strings.Join(parts[:len(parts)-1], "/")
	}

	switch {
	case containsAny(rtype, networkClusterKeywords):
		return "network/" + moduleDir, nil
	case containsAny(rtype, identityClusterKeywords):
		return "identity/" + moduleDir, nil
	case containsAny(rtype, dataClusterKeywords):
		return "data/" + moduleDir, nil
	case containsAny(rtype, computeClusterKeywords):
		return "compute/" + moduleDir, nil
	}
	return "general/" + moduleDir, nil
}

// BuildGraphFromInventory ports build_graph_from_inventory: read inventory.json
// and write graph.json deterministically.
//
// Returns (graphPath, totalNodes, totalEdges) — the Python tuple — plus an
// error for the failures Python raises on (open/json.load/makedirs/write).
func BuildGraphFromInventory(inventoryPath, outputDir string) (string, int, int, error) {
	raw, err := os.ReadFile(inventoryPath)
	if err != nil {
		return "", 0, 0, fmt.Errorf("cloudsecurity recon: reading %s: %w", inventoryPath, err)
	}
	decoded, err := pyfmt.Load(raw)
	if err != nil {
		return "", 0, 0, fmt.Errorf("cloudsecurity recon: parsing %s: %w", inventoryPath, err)
	}

	// Python: `if not isinstance(inv, dict): inv = {"resources": []}`, then the
	// same defensive shape checks on `resources` and on each element.
	inv, _ := decoded.(pyfmt.Ordered)
	var rawResources []any
	if v, ok := inv.Get("resources"); ok {
		rawResources, _ = v.([]any)
	}
	resources := make([]pyfmt.Ordered, 0, len(rawResources))
	for _, r := range rawResources {
		if m, ok := r.(pyfmt.Ordered); ok {
			resources = append(resources, m)
		}
	}

	// --- nodes ---
	nodes := []any{}
	resourceIDs := map[string]struct{}{}
	for _, r := range resources {
		rid := invString(r, "id")
		resourceIDs[rid] = struct{}{}

		securityAttrs := pyfmt.Ordered{}
		if cfg, ok := r.Get("config"); ok {
			if cfgMap, isMap := cfg.(pyfmt.Ordered); isMap {
				for _, kv := range cfgMap {
					if containsAny(strings.ToLower(kv.K), configSummaryKeywords) {
						securityAttrs = append(securityAttrs, kv)
					}
				}
			}
		}

		// Python parity: the node dict COPIES these three through without a
		// string operation, so a non-string one does not raise here — it
		// raises later, in _infer_edge_type or _cluster_key.
		nodes = append(nodes, pyfmt.Ordered{
			{K: "resource_id", V: rid},
			{K: "resource_type", V: invString(r, "type")},
			{K: "provider", V: invString(r, "provider")},
			{K: "file_path", V: invString(r, "file_path")},
			{K: "config_summary", V: securityAttrs},
		})
	}

	// --- edges ---
	edges := []any{}
	seenEdges := map[string]struct{}{}
	for _, r := range resources {
		sourceID := invString(r, "id")
		sourceType := invString(r, "type")

		refs, err := invStrings(r, "references")
		if err != nil {
			return "", 0, 0, err
		}
		for _, ref := range refs {
			if _, known := resourceIDs[ref]; known && ref != sourceID {
				edgeKey := sourceID + "->" + ref
				if _, seen := seenEdges[edgeKey]; !seen {
					seenEdges[edgeKey] = struct{}{}
					edges = append(edges, pyfmt.Ordered{
						{K: "source", V: sourceID},
						{K: "target", V: ref},
						{K: "type", V: inferEdgeType(sourceType, ref)},
					})
				}
			}
		}
		refBys, err := invStrings(r, "referenced_by")
		if err != nil {
			return "", 0, 0, err
		}
		for _, refBy := range refBys {
			if _, known := resourceIDs[refBy]; known && refBy != sourceID {
				edgeKey := refBy + "->" + sourceID
				if _, seen := seenEdges[edgeKey]; !seen {
					seenEdges[edgeKey] = struct{}{}
					edges = append(edges, pyfmt.Ordered{
						{K: "source", V: refBy},
						{K: "target", V: sourceID},
						{K: "type", V: inferEdgeType(refBy, sourceType)},
					})
				}
			}
		}
	}

	// --- clusters ---
	clusterMap := map[string][]any{}
	for _, r := range resources {
		ck, err := clusterKey(r)
		if err != nil {
			return "", 0, 0, err
		}
		clusterMap[ck] = append(clusterMap[ck], invString(r, "id"))
	}
	clusterNames := make([]string, 0, len(clusterMap))
	for name := range clusterMap {
		clusterNames = append(clusterNames, name)
	}
	sort.Strings(clusterNames) // Python: sorted(cluster_map.items())
	clusters := []any{}
	for _, name := range clusterNames {
		clusters = append(clusters, pyfmt.Ordered{
			{K: "name", V: name},
			{K: "members", V: clusterMap[name]},
		})
	}

	graph := pyfmt.Ordered{
		{K: "nodes", V: nodes},
		{K: "edges", V: edges},
		{K: "clusters", V: clusters},
	}

	if err := os.MkdirAll(outputDir, 0o777); err != nil {
		return "", 0, 0, fmt.Errorf("cloudsecurity recon: creating %s: %w", outputDir, err)
	}
	graphPath := filepath.Join(outputDir, "graph.json")
	if err := os.WriteFile(graphPath, []byte(pyfmt.Dumps(graph, 2)), 0o666); err != nil {
		return "", 0, 0, fmt.Errorf("cloudsecurity recon: writing %s: %w", graphPath, err)
	}

	return graphPath, len(nodes), len(edges), nil
}

// invString is Python's `r.get(key, "")` for a value that is only ever COPIED
// into the graph document, never used in a string operation: a missing key, a
// null or a non-string all render as "".
//
// DIVERGENCE (verified against the repo venv, deliberately kept): Python copies
// such a value through unchanged, so an inventory whose resource has `"id": 7`
// produces `"resource_id": 7` in graph.json and does NOT raise. Go writes "".
// Reproducing it would mean carrying `any` ids through resource_ids, the
// seen_edges keys and the cluster members — where an unhashable id would panic
// instead of raising Python's TypeError. Only `id` and `provider` reach this
// helper; every value Python performs a string operation on goes through invStr
// and RAISES, because that raise is what selects the harness fallback.
func invString(o pyfmt.Ordered, key string) string {
	v, ok := o.Get(key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// invStr is Python's `r.get(key, "")` for a value the code then performs a
// STRING operation on (`file_path.split`, `kw in rtype`).
//
// The second result is the Python type name of a present-but-not-a-str value
// ("" when the value is a str or the key is absent, both of which Python
// tolerates). The caller turns it into the exact exception message Python
// raises at its own call site, so the diagnostic the harness fallback logs
// matches.
func invStr(o pyfmt.Ordered, key string) (string, string) {
	v, ok := o.Get(key)
	if !ok {
		// Python: the "" default, on which .split and `in` both work.
		return "", ""
	}
	if s, isStr := v.(string); isStr {
		return s, ""
	}
	return "", pyTypeName(v)
}

// invStrings ports the ITERATION `for ref in r.get(key, [])`, not a typed read.
//
// Python duck-types the loop, so the port has to as well (all verified against
// the repo venv on src/cloudsecurity_af/agents/recon/_graph_builder_fast.py):
//
//	absent / []      -> no iterations
//	list             -> its elements
//	str  "b"         -> its CHARACTERS ("b" therefore yields the ref "b")
//	dict {"b": 1}    -> its KEYS
//	None, int, float,
//	bool             -> TypeError: '<type>' object is not iterable
//
// The TypeError is the point: run_resource_graph_builder catches it and falls
// back to the LLM harness, where coercing to "no references" would instead
// return a successful, silently edge-less graph (total_edges: 0, every hunter
// prompt saying "no edges matched this hunter domain") with no warning.
//
// Non-string ELEMENTS are dropped rather than compared: `ref in resource_ids`
// is a set-of-str membership test, so a non-string element can only match a
// non-string id, which invString has already coerced away.
func invStrings(o pyfmt.Ordered, key string) ([]string, error) {
	v, ok := o.Get(key)
	if !ok {
		return nil, nil
	}
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, it := range x {
			if s, isStr := it.(string); isStr {
				out = append(out, s)
			}
		}
		return out, nil
	case string:
		out := make([]string, 0, len(x))
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	case pyfmt.Ordered:
		out := make([]string, 0, len(x))
		for _, kv := range x {
			out = append(out, kv.K)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("'%s' object is not iterable", pyTypeName(v))
	}
}

// pyTypeName is type(v).__name__ for the value model pyfmt.Load produces
// (nil | bool | string | int | json.Number | float64 | []any | pyfmt.Ordered).
func pyTypeName(v any) string {
	switch n := v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case string:
		return "str"
	case int:
		return "int"
	case json.Number:
		// An arbitrary-precision Python int, or a number whose literal was kept
		// verbatim (see pyfmt.loadNumber).
		if !strings.ContainsAny(string(n), ".eE") {
			return "int"
		}
		return "float"
	case float64:
		return "float"
	case []any:
		return "list"
	case pyfmt.Ordered:
		return "dict"
	}
	return fmt.Sprintf("%T", v)
}
