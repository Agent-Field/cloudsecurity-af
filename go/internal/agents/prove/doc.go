// Package prove ports src/cloudsecurity_af/agents/prove/** — the PROVE phase's
// two verifiers.
//
//	Python                                       Go
//	------------------------------------------   ------------------------------
//	prove/static_prover.run_static_prover        RunStaticProver
//	prove/static_prover._build_prompt            BuildStaticProverPrompt
//	prove/live_prover.run_live_prover            RunLiveProver
//	prove/live_prover._build_prompt              BuildLiveProverPrompt
//
// The two Run* functions are what internal/reasoners wraps as the
// `run_static_prover` and `run_live_prover` router reasoners; internal/phases
// picks ONE of them per finding — static for tier < 2, live for tier >= 2 — and
// drives it through app.Call, never in-process, exactly as prove_phase does in
// Python.
//
// # The two agents are the same code twice
//
// static_prover.py and live_prover.py are byte-for-byte identical apart from
// three constants: the prompt template, the tempdir prefix and the
// extract_harness_result agent name. Python duplicates the whole module
// (including a private `_build_prompt` with the same 13 replacements in the same
// order); the Go port keeps ONE implementation, buildProverPrompt, and two thin
// exported builders that differ only in which template they load. The observable
// behavior is unchanged — that is verified by golden fixtures generated from
// BOTH Python modules independently.
//
// # What a prover does and does not do
//
// It renders a prompt, runs ONE harness call with cwd=<fresh tempdir> and
// project_dir=<repo>, and returns whatever VerifiedFinding the model produced.
// There is no deterministic pre-processing and NO post-processing: the verdict,
// severity, risk_score, sarif_rule_id and sarif_security_severity all come
// straight out of the model (the prompt's MANDATORY FIELDS block is the only
// thing that asks for them). In particular the
// `cloudsecurity/<hunter_strategy>/<category>` SARIF rule id that the design
// notes mention is NOT synthesized here — it is applied in two other places,
// both owned by other packages:
//
//   - reasoners/phases.py `_fallback_verified` mints it when a prover call
//     FAILED and the phase has to fabricate an inconclusive finding, and
//   - output/sarif.py falls back to it whenever `finding.sarif_rule_id` is
//     empty at report time.
//
// A prover returning an empty sarif_rule_id is therefore normal and must not be
// "fixed up" here.
//
// # Divergences from Python, in one place
//
//  1. Parameter ORDER. Python's agent function is
//     `run_static_prover(app, repo_path, finding, attack_path, tier)`, but its
//     `@router.reasoner()` wrapper — the signature the control plane and every
//     caller actually see — is `(repo_path, finding, tier, attack_path=None)`.
//     The Go port follows the REASONER order, so attackPath is last and
//     optional-looking, matching the call sites in internal/reasoners and the
//     port's cross-package contract. Nothing observable depends on it.
//  2. The two json.dumps sites go through pyfmt.Dumps, whose documented
//     deviations are: `Any`-typed leaves that arrived as JSON numbers are
//     float64 in Go, so an integer renders as "1.0" where Python renders "1"
//     (only reachable through a DriftedResource nested in an AttackPath); and a
//     Go map has no insertion order, so a map[string]any inside a finding is
//     dumped with SORTED keys. Struct field order — which is what model_dump()
//     order actually is — is preserved exactly.
//  3. pyfmt.Dumps renders a NIL Go slice as `null` where pydantic's
//     default_factory=list guarantees `[]`. It cannot fire in the live DAG —
//     every finding reaching a prover crossed a control-plane JSON boundary and
//     was re-seeded by RawFinding.UnmarshalJSON — but a Go caller handing in a
//     hand-built struct literal would see it. Pinned by
//     TestBuildProverPrompt_NilSliceRendersNull.
//
// Everything else — the prompt bytes, the substitution ORDER, the tempdir
// prefixes, the cwd/project_dir pair, the extract agent names ("StaticProver" /
// "LiveProver") and the cleanup semantics — is byte-for-byte the Python
// behavior.
package prove
