// Package phases ports src/cloudsecurity_af/reasoners/phases.py — the five
// phase reasoners (recon_phase, hunt_phase, chain_phase, prove_phase,
// remediation_phase) that fan the scan out across the individual agent
// reasoners.
//
// These functions ARE the DAG's second level. Every place the Python source
// does
//
//	await _runtime_router.call(f"{NODE_ID}.run_x", **kwargs)
//
// the Go port does
//
//	app.Call(ctx, nodeID+".run_x", map[string]any{...})
//
// with the SAME target name and the SAME kwargs keys, so the control plane
// records an identical parent→child execution tree. A phase NEVER calls the
// agent function in-process; doing so would collapse a DAG node.
//
// Parity notes that apply package-wide:
//
//   - Envelope handling. Python's phases.py defines its own _unwrap, the
//     STRICT variant that also fails on `error_message` and on
//     `status in ("failed", "error")`. Every call site here goes through
//     afx.UnwrapStrict + afx.AsMap, which are the exact ports of that pair,
//     with the same error strings.
//   - Model materialization. `Model.model_validate(payload)` becomes
//     afx.Bind[Model](payload), whose UnmarshalJSON seeds the pydantic
//     defaults AND — unlike a bare json.Unmarshal — RAISES on a missing
//     required field, exactly as pydantic does. afx.Bind walks the payload
//     against the model tree first (internal/afx/required.go) and returns an
//     *afx.ValidationError wrapping an *afx.MissingFieldError, the stand-in for
//     pydantic's ValidationError with type=missing; only the message TEXT
//     differs (no input value, no docs URL). So a malformed iac-reader reply
//     missing ResourceInventory.inventory_saved_path aborts recon_phase here
//     the way it aborts it in Python, rather than carrying an empty path into
//     run_resource_graph_builder. prove_phase depends on the same raise to take
//     its `_fallback_verified(finding, "Schema parse failed: ...")` branch, and
//     internal/orch depends on it for app.py's 400 (ValueError) branch — see
//     orch's TestBindVerifiedList_MissingRequiredFieldsRaise. The one genuine
//     narrowing is scope, not behavior: a model is checked only against the
//     required list it declares via afx.RequiredFielder, and internal/schemas'
//     required_test.go cross-checks every declared list against the committed
//     pydantic schema fixtures' `required` arrays. Python parity: `missing`
//     fires on an ABSENT key; a key present with an explicit null is a type
//     error, left to the decode.
//   - Concurrency. asyncio.Semaphore(n) becomes a buffered channel of
//     capacity n; asyncio.gather becomes a sync.WaitGroup writing into a
//     pre-indexed result slice, so results keep ARGUMENT order rather than
//     completion order (gather does the same). Nothing here cancels ctx on the
//     first error, because asyncio.gather does not cancel its siblings either.
//   - Depth. Every phase normalizes its `depth` string with
//     config.NormalizeDepth (the _normalize_depth port): lowercased, and
//     anything unrecognized silently becomes "standard".
//   - NODE_ID. phases.py reads NODE_ID ONCE at import time into a module
//     constant. The Go phases take nodeID as an explicit parameter so nothing
//     is frozen at init and tests are deterministic; NodeID() reproduces the
//     env lookup for callers that want it.
//
// The phases take the narrowest capability they need — appx.Caller — because
// not one of them uses harness, ai or note. (In particular hunt_phase swallows
// hunter failures WITHOUT emitting a note; the port must not add one.)
package phases
