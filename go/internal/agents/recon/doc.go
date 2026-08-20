// Package recon ports src/cloudsecurity_af/agents/recon/** — the RECON phase's
// four agents plus the two deterministic engines they prefer over the LLM.
//
//	Python                                        Go
//	-------------------------------------------   ---------------------------------
//	recon/_terraform_parser.parse_terraform_...   ParseTerraformDirectory  (tfparse.go)
//	recon/_graph_builder_fast.build_graph_from... BuildGraphFromInventory  (graphfast.go)
//	recon/iac_reader.run_iac_reader               RunIaCReader             (iac_reader.go)
//	recon/resource_graph_builder.run_resource_... RunResourceGraphBuilder  (resource_graph_builder.go)
//	recon/cloud_connector.run_cloud_connector     RunCloudConnector        (cloud_connector.go)
//	recon/drift_detector.run_drift_detector       RunDriftDetector         (drift_detector.go)
//
// The four Run* functions are what internal/reasoners wraps as the
// `run_iac_reader`, `run_resource_graph_builder`, `run_cloud_connector` and
// `run_drift_detector` router reasoners; internal/phases drives them through
// app.Call, never in-process, exactly as recon_phase does in Python.
//
// SHAPE OF THE PHASE. run_iac_reader and run_resource_graph_builder each try a
// deterministic, offline path first (a real Terraform parse; a pure function
// over inventory.json) and only fall back to the harness when that raises. The
// two Tier-2 agents, run_cloud_connector and run_drift_detector, are
// harness-only — they enumerate a live cloud account, which no local parser can
// do.
//
// # Divergences from Python, in one place
//
//  1. NON-CONSTANT TERRAFORM EXPRESSIONS. Python renders them as pyhcl2 AST
//     reprs (with source byte offsets); Go renders them as their source text.
//     This is the design contract's instruction and the only change with
//     observable downstream effects — `references`, `referenced_by` and the
//     graph's edges differ. Read the long note on exprToValue in tfparse.go for
//     the full accounting, and TestParseTerraformDirectory_ReferenceDivergence
//     for the exact per-resource delta on the checked-in fixture.
//  2. `null` and negated numeric literals evaluate in Go and stringify to a
//     repr in Python. Same root cause as (1).
//  3. Heredoc bodies keep their `<<-EOT ... EOT` wrapper in Go where pyhcl2
//     hands back the dedented body.
//  4. Object key order is preserved everywhere it is observable (pyfmt.Load
//     decodes into pyfmt.Ordered and pyfmt.Dumps writes that order back out);
//     the only sorted-instead-of-insertion-ordered cases are values Go cannot
//     recover an order for, each commented at its site.
//  5. Log lines for the fallback warnings are formatted by the Go port rather
//     than by Python's logging module; the message text is verbatim.
//  6. `json.dump(inventory, f, indent=2, default=str)`'s `default=str` arm has
//     no Go counterpart. This package used to carry its own json.dumps copy
//     that rendered an unknown Go type as a JSON string; it was folded into
//     pyfmt.Dumps at integration time, and pyfmt.Dumps walks an unknown struct
//     into a JSON object instead. Unreachable in practice: ctyToValue maps
//     every Terraform value into
//     `nil | bool | string | int | float64 | []any | pyfmt.Ordered` before it is
//     written, and orderCloudConfig only ever holds JSON-decoded values, so no
//     output byte changes. The Python-ground-truth table that pinned the old
//     copy now lives in internal/pyfmt/pyjson_valuemodel_test.go.
//
// Everything else — resource ids, types, names, provider mapping, file paths,
// the inventory/graph key sets and their order, cluster keys, edge-type
// inference, the four prompt strings, the harness Cwd/ProjectDir, the temp-dir
// prefixes, the extract error strings and which work dirs are cleaned up — is
// byte-for-byte the Python behavior.
package recon
