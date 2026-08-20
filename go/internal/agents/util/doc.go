// Package util ports the non-harness half of src/cloudsecurity_af/agents/_utils.py.
//
//	Python                                       Go
//	------------------------------------------   ---------------------------------
//	_utils.extract_harness_result                harnessx.Extract   (foundation pkg)
//	_utils.build_graph_context_for_hunter        BuildGraphContextForHunter
//
// extract_harness_result deliberately does NOT live here: the design contract
// maps it onto internal/harnessx, where it is fused with the app.harness call
// as harnessx.RunExtract. What is left in _utils.py is one pure function —
// build_graph_context_for_hunter — which every one of the seven HUNT agents
// calls to turn the RECON phase's graph.json + inventory.json into the three
// text blocks its prompt template interpolates.
//
// # Why this needs a Python-JSON value model
//
// The function renders each node's `config_summary` with an f-string:
//
//	node_lines.append(f"    Config: {node.get('config_summary')}")
//
// and `config_summary` is a DICT in the file the RECON graph builder writes
// (see internal/agents/recon/graphfast.go), so the rendered text is a CPython
// dict repr whose KEY ORDER is the order the attributes appear in the .tf file.
// Decoding the file into map[string]any would destroy that order and change the
// bytes the LLM sees, so this package carries an order-preserving decoder
// (pyfmt.Load) producing pyfmt.Ordered objects, and renders through
// pyfmt.Str — Python's str(), i.e. exactly what an f-string interpolation does.
//
// # Additions beyond the Python file
//
// ResolvePath (path.go) is NOT a port of anything in _utils.py: it is the
// shared implementation of `str(Path(p).resolve())`, which the seven hunters
// need for their harness Cwd and which app.py / orchestrator.py also use. It
// lives here so there is exactly one copy in the port.
package util
