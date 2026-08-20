// Package chain ports src/cloudsecurity_af/agents/chain/** — the CHAIN phase,
// CloudSecurity AF's key differentiator.
//
//	Python                                          Go
//	---------------------------------------------   --------------------------------
//	chain/path_constructor.run_path_constructor     RunPathConstructor
//	chain/path_constructor._build_parent_prompt     BuildParentPrompt
//	chain/path_constructor._child_prompt            BuildChildPrompt
//	chain/path_constructor._compact_finding         compactFinding
//	chain/path_constructor._filter_graph_for_...    filterGraphForFindings
//
// RunPathConstructor is what internal/reasoners wraps as the
// `run_path_constructor` router reasoner; internal/phases drives it through
// app.Call from chain_phase, never in-process, exactly as Python does.
//
// # Shape of the phase
//
// CHAIN is meta-prompting: ONE parent harness call plans up to max_children
// "investigations" (each a free-text child prompt written by the model), then
// every investigation is dispatched as its OWN harness call that must return a
// single AttackPath. The children run concurrently and unbounded — Python's
// asyncio.gather with no semaphore — and a child that fails for any reason is
// silently dropped rather than failing the phase. Only the parent call can fail
// the phase.
//
// The two pydantic models the parent call is schema'd against
// (PathInvestigationPlan, ChildInvestigation) are declared in this Python module
// rather than in schemas/, but the Go port keeps them in internal/schemas: they
// cross a JSON boundary, so harnessx has to resolve their committed pydantic
// schema fixture by Go type name. See internal/schemas/pathplan.go.
//
// # Divergences from Python, in one place
//
// The three json.dumps sites here go through pyfmt.Dumps, which carries the
// port's json.dumps parity contract (ensure_ascii escaping, Python float repr,
// insertion-ordered pyfmt.Ordered objects). Its two documented deviations reach
// this package:
//
//  1. `Any`-typed leaves inside a DriftReport (ConfigDiff.iac_value,
//     DriftedResource.iac_config values) that arrived as JSON numbers are
//     float64 in Go, so an integer renders as "1.0" where Python renders "1".
//  2. A Go map has no insertion order, so a map[string]any inside a drift report
//     is dumped with SORTED keys. Every object whose order Python actually
//     controls (the compact-finding dicts, the filtered graph, the graph file
//     read back from disk) is modeled as a pyfmt.Ordered — see pyload.go — and
//     keeps its order.
//
// And one of this package's own:
//
//  3. Graph-file node/edge ids that are NOT strings are treated as "not a
//     member" of the relevant-id set; Python would either match them (if some
//     other id had the same non-string value) or raise TypeError (for an
//     unhashable one). No graph this port can produce contains such an id.
//
// A fourth, latent one: pyfmt.Dumps renders a NIL Go slice as `null` where
// pydantic's default_factory=list guarantees `[]`. It cannot fire in the live
// DAG — every model reaching these builders crossed a control-plane JSON
// boundary and was re-seeded by its UnmarshalJSON — but a Go caller handing in a
// hand-built struct literal would see it.
//
// Everything else — the prompt bytes, the substitution ORDER, the temp-dir
// prefix, which harness calls get a project_dir (none do here), the extract
// agent names, the truncation rules, the duration rounding and the ChainResult
// key set — is byte-for-byte the Python behavior.
package chain
