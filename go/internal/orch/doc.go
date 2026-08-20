// Package orch ports src/cloudsecurity_af/orchestrator.py — the ScanOrchestrator
// that drives one CloudSecurity scan end to end.
//
// Run() is THE DAG driver: five sequential `app.call`s, one per phase, each with
// exactly the kwargs Python passes. Nothing here calls a phase function
// in-process; every phase is a control-plane child execution, which is what
// makes the workflow tree in the UI identical to the Python node's.
//
//	scan / prove
//	├── recon_phase
//	├── hunt_phase
//	├── chain_phase
//	├── prove_phase
//	└── remediation_phase
//
// Parity notes that apply package-wide:
//
//   - Envelope handling uses afx.UnwrapStrict + afx.AsMap, the exact ports of
//     the _unwrap/_as_dict pair orchestrator.py defines at module scope (a
//     byte-identical copy of the pair in reasoners/phases.py).
//   - NODE_ID is read inside Run(), exactly as Python's
//     `node_id = os.getenv("NODE_ID", "cloudsecurity")` does.
//   - time.monotonic() becomes a nowFn seam defaulting to time.Now, whose
//     result carries Go's monotonic reading; datetime.now(UTC) becomes
//     schemas.NewTimestamp(nowFn().UTC()). Both are injectable for tests and
//     neither changes live behaviour.
//   - app.py MUTATES repo_path and checkpoint_dir after constructing the
//     orchestrator, so RepoPath and CheckpointDir are exported settable fields.
//     Config.RepoPath deliberately keeps the CLOUDSECURITY_REPO_PATH/cwd value
//     New() computed — Python never re-derives it either.
//   - _emit_progress builds a ScanProgress and DROPS it. It is ported as a
//     builder that returns the value and emits nothing, so the (unused) math is
//     still covered by tests and a future `app.note` wiring has a home.
//   - _PhaseHarnessProxy exists in Python but no code path reaches it; it is
//     ported minimally, for the budget/cost bookkeeping it documents.
package orch
