package recon

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// VALIDATION CONTRACT for BuildGraphFromInventory (from
// build_graph_from_inventory in _graph_builder_fast.py):
//
//  1. One node per inventory resource, in inventory order, carrying
//     {resource_id, resource_type, provider, file_path, config_summary}, where
//     config_summary is the config entries — IN CONFIG ORDER — whose lowercased
//     key contains one of the 17 security keywords.
//  2. One edge per (resource -> reference) and per (referenced_by -> resource)
//     where the other end is a known resource id and is not the resource itself,
//     de-duplicated on "<source>-><target>", first occurrence wins.
//  3. Edge type = the FIRST _EDGE_TYPE_MAP keyword (in declaration order) that
//     is a substring of either end, else "references".
//  4. Clusters group resources by _cluster_key and are emitted sorted by name;
//     members keep inventory order.
//  5. The file is graph.json inside output_dir, json.dump(..., indent=2).
//  6. The return value is (path, len(nodes), len(edges)).
//  7. Malformed inventories degrade to empty lists rather than raising.

const pythonGraphFixture = "testdata/python/graph.json"

// The strongest available assertion: given the SAME input the Python builder
// consumed, the Go builder must produce the SAME BYTES. This isolates the
// port's only behavioral divergence to the Terraform parser — the graph builder
// itself is exact.
func TestBuildGraphFromInventory_ByteIdenticalToPythonOnPythonInventory(t *testing.T) {
	out := t.TempDir()
	graphPath, nodes, edges, err := BuildGraphFromInventory(pythonInventoryFixture, out)
	if err != nil {
		t.Fatalf("BuildGraphFromInventory: %v", err)
	}

	got, err := os.ReadFile(graphPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(pythonGraphFixture)
	if err != nil {
		t.Fatalf("reading %s (regenerate with go/scripts/gen_golden.py): %v", pythonGraphFixture, err)
	}
	if string(got) != string(want) {
		t.Errorf("graph.json differs from Python's byte-for-byte\n--- go ---\n%s\n--- python ---\n%s", got, want)
	}

	// Contract items 5 and 6.
	if graphPath != filepath.Join(out, "graph.json") {
		t.Errorf("graph path = %q, want %q", graphPath, filepath.Join(out, "graph.json"))
	}
	summary := loadPythonFixture(t, pythonSummaryFixture)
	if wantNodes, _ := summary.Get("total_nodes"); nodes != wantNodes {
		t.Errorf("total_nodes = %d, Python says %v", nodes, wantNodes)
	}
	if wantEdges, _ := summary.Get("total_edges"); edges != wantEdges {
		t.Errorf("total_edges = %d, Python says %v", edges, wantEdges)
	}
}

// Contract items 1-4 driven by the Go parser's own inventory, which is where the
// reference divergence shows up: Go's richer reference set yields more edges.
func TestBuildGraphFromInventory_OnTheGoParsersInventory(t *testing.T) {
	work := t.TempDir()
	invPath, _, _, err := ParseTerraformDirectory(vulnerableInfraFixture, work)
	if err != nil {
		t.Fatal(err)
	}
	graphPath, nodes, edges, err := BuildGraphFromInventory(invPath, work)
	if err != nil {
		t.Fatal(err)
	}
	if nodes != 7 {
		t.Errorf("nodes = %d, want 7 (one per resource, same as Python)", nodes)
	}
	// Python reports 1 edge because its AST-repr config hides the traversals;
	// the Go parser surfaces them, so the graph gains the five real ones.
	if edges != 6 {
		t.Errorf("edges = %d, want 6", edges)
	}

	graph := decodeGraph(t, graphPath)
	gotEdges := map[string]string{}
	for _, e := range sectionOf(t, graph, "edges") {
		obj := asObject(t, e)
		src := pyfmt.Str(mustGet(t, obj, "source"))
		dst := pyfmt.Str(mustGet(t, obj, "target"))
		gotEdges[src+"->"+dst] = pyfmt.Str(mustGet(t, obj, "type"))
	}
	// "iam" is the first _EDGE_TYPE_MAP keyword, so anything IAM-shaped at
	// either end is "trust" even when the other end is a bucket. The
	// public-access-block pair matches on "policy", also a trust keyword.
	wantEdges := map[string]string{
		"aws_instance.web_server->aws_iam_instance_profile.web_profile":                      "trust",
		"aws_instance.web_server->aws_security_group.allow_all":                              "network_path",
		"aws_iam_instance_profile.web_profile->aws_iam_role.web_role":                        "trust",
		"aws_iam_role_policy.s3_full_access->aws_iam_role.web_role":                          "trust",
		"aws_iam_role_policy.s3_full_access->aws_s3_bucket.customer_data":                    "trust",
		"aws_s3_bucket_public_access_block.customer_data_block->aws_s3_bucket.customer_data": "data_access",
	}
	if !reflect.DeepEqual(gotEdges, wantEdges) {
		t.Errorf("edges = %#v\n    want %#v", gotEdges, wantEdges)
	}
}

// Contract item 3.
func TestInferEdgeType(t *testing.T) {
	// The first _EDGE_TYPE_MAP keyword that is a substring of EITHER string
	// decides; the comment on each row names the winning keyword.
	cases := []struct {
		source, target, want string
	}{
		{"aws_iam_role", "aws_s3_bucket.x", "trust"},                  // iam
		{"aws_s3_bucket", "aws_iam_role.x", "trust"},                  // iam, matched on the TARGET
		{"aws_security_group", "aws_instance.x", "network_path"},      // security_group
		{"aws_s3_bucket", "aws_s3_bucket.x", "data_access"},           // bucket
		{"aws_lambda_function", "aws_lambda_function.x", "execution"}, // lambda
		{"nothing_matches", "also_nothing", "references"},             // nothing
	}

	for _, tc := range cases {
		if got := inferEdgeType(tc.source, tc.target); got != tc.want {
			t.Errorf("inferEdgeType(%q, %q) = %q, want %q", tc.source, tc.target, got, tc.want)
		}
	}

	// Declaration order is load-bearing: "role" (trust) precedes "subnet"
	// (network_path), and "policy" (trust) precedes "s3" (data_access).
	if got := inferEdgeType("aws_db_subnet_group", "aws_iam_role.x"); got != "trust" {
		t.Errorf(`"role" must win over "subnet"; got %q`, got)
	}
	if got := inferEdgeType("aws_s3_bucket_policy", ""); got != "trust" {
		t.Errorf(`"policy" must win over "s3"/"bucket"; got %q`, got)
	}
}

// Contract item 4.
func TestClusterKey(t *testing.T) {
	cases := []struct {
		rtype, filePath, want string
	}{
		{"aws_vpc", "main.tf", "network/root"},
		{"aws_security_group", "net/sg.tf", "network/net"},
		{"aws_iam_role", "main.tf", "identity/root"},
		{"aws_s3_bucket", "modules/data/main.tf", "data/modules/data"},
		{"aws_lambda_function", "main.tf", "compute/root"},
		// "group" is an IDENTITY keyword, so a CloudWatch log GROUP clusters as
		// identity — surprising, and exactly what Python does.
		{"aws_cloudwatch_log_group", "main.tf", "identity/root"},
		// "flow_log" is a NETWORK keyword and is checked first, so a VPC flow
		// log clusters as network even though "log" reads like observability.
		{"aws_flow_log", "main.tf", "network/root"},
		// "policy" is an identity keyword; an s3 bucket policy is identity, not
		// data, because identity is tested before data.
		{"aws_s3_bucket_policy", "main.tf", "identity/root"},
		// An empty file_path splits into ONE part, so module_dir is "root".
		{"aws_instance", "", "compute/root"},
		{"aws_instance", "main.tf", "compute/root"},
		{"unknown_thing", "a/b/c.tf", "general/a/b"},
	}
	for _, tc := range cases {
		res := pyfmt.Ordered{{K: "type", V: tc.rtype}, {K: "file_path", V: tc.filePath}}
		got, err := clusterKey(res)
		if err != nil {
			t.Errorf("clusterKey(%q, %q): %v", tc.rtype, tc.filePath, err)
			continue
		}
		if got != tc.want {
			t.Errorf("clusterKey(%q, %q) = %q, want %q", tc.rtype, tc.filePath, got, tc.want)
		}
	}
}

// Contract item 1: config_summary keeps CONFIG order, not alphabetical order,
// because it is interpolated into hunter prompts as a Python dict repr.
func TestBuildGraphFromInventory_ConfigSummaryFiltersAndKeepsOrder(t *testing.T) {
	inv := pyfmt.Ordered{{K: "resources", V: []any{
		pyfmt.Ordered{
			{K: "id", V: "aws_s3_bucket.b"},
			{K: "type", V: "aws_s3_bucket"},
			{K: "provider", V: "aws"},
			{K: "file_path", V: "main.tf"},
			{K: "config", V: pyfmt.Ordered{
				{K: "zzz_encryption", V: true}, // "encrypt"
				{K: "bucket", V: "x"},          // no keyword -> dropped
				{K: "AclSetting", V: "public"}, // "acl", matched case-insensitively
				{K: "tags", V: pyfmt.Ordered{}},
				{K: "aaa_versioning", V: false}, // "versioning"
			}},
			{K: "references", V: []any{}},
			{K: "referenced_by", V: []any{}},
		},
	}}}

	dir := t.TempDir()
	invPath := filepath.Join(dir, "inventory.json")
	if err := os.WriteFile(invPath, []byte(pyfmt.Dumps(inv, 2)), 0o666); err != nil {
		t.Fatal(err)
	}
	graphPath, nodes, edges, err := BuildGraphFromInventory(invPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	if nodes != 1 || edges != 0 {
		t.Fatalf("(nodes, edges) = (%d, %d), want (1, 0)", nodes, edges)
	}

	graph := decodeGraph(t, graphPath)
	node := asObject(t, sectionOf(t, graph, "nodes")[0])
	summary := asObject(t, mustGet(t, node, "config_summary"))

	gotKeys := make([]string, len(summary))
	for i, kv := range summary {
		gotKeys[i] = kv.K
	}
	want := []string{"zzz_encryption", "AclSetting", "aaa_versioning"}
	if !reflect.DeepEqual(gotKeys, want) {
		t.Errorf("config_summary keys = %v, want %v (config order, keyword-filtered)", gotKeys, want)
	}
}

// Contract item 2: both directions produce edges, self-edges and unknown ends
// are skipped, and the "<source>-><target>" key de-duplicates.
func TestBuildGraphFromInventory_EdgeConstruction(t *testing.T) {
	res := func(id string, refs, refBy []any) pyfmt.Ordered {
		return pyfmt.Ordered{
			{K: "id", V: id},
			{K: "type", V: id},
			{K: "provider", V: "aws"},
			{K: "file_path", V: "main.tf"},
			{K: "config", V: pyfmt.Ordered{}},
			{K: "references", V: refs},
			{K: "referenced_by", V: refBy},
		}
	}
	inv := pyfmt.Ordered{{K: "resources", V: []any{
		// a -> b twice (deduplicated), a -> itself (skipped), a -> ghost (unknown, skipped)
		res("a", []any{"b", "b", "a", "ghost"}, []any{}),
		// b's referenced_by re-states a -> b, which is already seen.
		res("b", []any{}, []any{"a", "a", "b", "ghost"}),
		// c only appears through its referenced_by, which creates b -> c.
		res("c", []any{}, []any{"b"}),
	}}}

	dir := t.TempDir()
	invPath := filepath.Join(dir, "inventory.json")
	if err := os.WriteFile(invPath, []byte(pyfmt.Dumps(inv, 2)), 0o666); err != nil {
		t.Fatal(err)
	}
	graphPath, _, edges, err := BuildGraphFromInventory(invPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	if edges != 2 {
		t.Fatalf("edges = %d, want 2", edges)
	}

	graph := decodeGraph(t, graphPath)
	var pairs []string
	for _, e := range sectionOf(t, graph, "edges") {
		obj := asObject(t, e)
		pairs = append(pairs, pyfmt.Str(mustGet(t, obj, "source"))+"->"+pyfmt.Str(mustGet(t, obj, "target")))
	}
	if want := []string{"a->b", "b->c"}; !reflect.DeepEqual(pairs, want) {
		t.Errorf("edges = %v, want %v", pairs, want)
	}
}

// Contract item 4: clusters sorted by name, members in inventory order.
func TestBuildGraphFromInventory_ClustersSortedByName(t *testing.T) {
	work := t.TempDir()
	invPath, _, _, err := ParseTerraformDirectory(vulnerableInfraFixture, work)
	if err != nil {
		t.Fatal(err)
	}
	graphPath, _, _, err := BuildGraphFromInventory(invPath, work)
	if err != nil {
		t.Fatal(err)
	}

	graph := decodeGraph(t, graphPath)
	var names []string
	for _, c := range sectionOf(t, graph, "clusters") {
		names = append(names, pyfmt.Str(mustGet(t, asObject(t, c), "name")))
	}
	want := []string{"compute/root", "data/root", "identity/root", "network/root"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("cluster names = %v, want %v", names, want)
	}

	identity := asObject(t, sectionOf(t, graph, "clusters")[2])
	members := stringsOf(mustGet(t, identity, "members"))
	wantMembers := []string{
		"aws_iam_role.web_role",
		"aws_iam_instance_profile.web_profile",
		"aws_iam_role_policy.s3_full_access",
	}
	if !reflect.DeepEqual(members, wantMembers) {
		t.Errorf("identity/root members = %v, want %v (inventory order)", members, wantMembers)
	}
}

// Contract item 7.
func TestBuildGraphFromInventory_MalformedInventoriesDegradeToEmpty(t *testing.T) {
	cases := map[string]string{
		"top level is a list":     `[1, 2, 3]`,
		"resources is not a list": `{"resources": {"a": 1}}`,
		"resources is absent":     `{"variables": []}`,
		"elements are not dicts":  `{"resources": [1, "two", null]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			invPath := filepath.Join(dir, "inventory.json")
			if err := os.WriteFile(invPath, []byte(body), 0o666); err != nil {
				t.Fatal(err)
			}
			graphPath, nodes, edges, err := BuildGraphFromInventory(invPath, dir)
			if err != nil {
				t.Fatalf("want a graceful empty graph, got %v", err)
			}
			if nodes != 0 || edges != 0 {
				t.Errorf("(nodes, edges) = (%d, %d), want (0, 0)", nodes, edges)
			}
			raw, err := os.ReadFile(graphPath)
			if err != nil {
				t.Fatal(err)
			}
			want := "{\n  \"nodes\": [],\n  \"edges\": [],\n  \"clusters\": []\n}"
			if string(raw) != want {
				t.Errorf("graph.json =\n%s\nwant\n%s", raw, want)
			}
		})
	}
}

// A missing or unreadable inventory is the failure that sends
// run_resource_graph_builder to its harness fallback, so it must be an error
// rather than an empty graph.
func TestBuildGraphFromInventory_MissingFileIsAnError(t *testing.T) {
	if _, _, _, err := BuildGraphFromInventory(filepath.Join(t.TempDir(), "nope.json"), t.TempDir()); err == nil {
		t.Error("want an error for a missing inventory, got nil")
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "inventory.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := BuildGraphFromInventory(bad, dir); err == nil {
		t.Error("want an error for an unparsable inventory, got nil")
	}
}

func decodeGraph(t *testing.T, path string) pyfmt.Ordered {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := pyfmt.Load(raw)
	if err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return asObject(t, decoded)
}
