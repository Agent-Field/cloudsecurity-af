// Package hunt ports src/cloudsecurity_af/agents/hunt/** — the seven
// domain-specialized HUNT agents.
//
//	Python                                     Go
//	----------------------------------------   ----------------------
//	hunt/iam_hunter.run_iam_hunter             RunIAMHunter
//	hunt/network_hunter.run_network_hunter     RunNetworkHunter
//	hunt/data_hunter.run_data_hunter           RunDataHunter
//	hunt/secrets_hunter.run_secrets_hunter     RunSecretsHunter
//	hunt/compute_hunter.run_compute_hunter     RunComputeHunter
//	hunt/logging_hunter.run_logging_hunter     RunLoggingHunter
//	hunt/compliance_hunter.run_compliance_hunter RunComplianceHunter
//
// internal/reasoners wraps these as the `run_iam_hunter` … `run_compliance_hunter`
// router reasoners; internal/phases drives them through app.Call under a
// semaphore, never in-process, exactly as hunt_phase does in Python.
//
// # The seven files are one function
//
// Every Python hunter file is a byte-for-byte copy of the others apart from
// four values: the prompt template path, the graph-context domain keywords, the
// agent name used in harness error messages, and the strategy label stamped
// onto strategies_run. hunter (hunt.go) captures exactly those four; each
// <name>_hunter.go holds only its own literals plus the exported entry point,
// so the file layout still maps 1:1 onto the Python package.
//
// # What a hunter does
//
//  1. Read its prompt template (Python does this at CALL time from the
//     installed package's prompts/ tree; Go serves it from internal/prompts,
//     which is embedded in the binary).
//  2. Turn the RECON artifacts (graph.json, inventory.json) into three text
//     blocks filtered to its domain — util.BuildGraphContextForHunter.
//  3. Interpolate the six placeholders, IN PYTHON'S ORDER (see buildPrompt).
//  4. Run the harness with schema=HuntResult, cwd = the RESOLVED repo path,
//     project_dir = the repo path as given.
//  5. Backfill total_raw / deduplicated_count from len(findings) when the model
//     left them at 0, and overwrite strategies_run with its own single label.
//
// There is no per-hunter post-processing beyond step 5: fingerprints,
// cross-hunter dedup and category handling all live in reasoners/phases.py
// (Go: internal/phases), not here.
//
// # No temp directory
//
// Unlike the RECON agents, a hunter does NOT create a work dir: it runs the
// harness with cwd = str(Path(repo_path).resolve()) and lets the SDK place the
// output file under project_dir. Nothing here to clean up.
package hunt
