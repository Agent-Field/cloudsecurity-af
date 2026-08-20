// Package remediate ports src/cloudsecurity_af/agents/remediate/** — the
// REMEDIATION phase's single agent.
//
//	Python                                       Go
//	------------------------------------------   ------------------------------
//	remediate/fix_generator.run_fix_generator    RunFixGenerator
//	remediate/fix_generator._build_prompt        BuildFixGeneratorPrompt
//
// RunFixGenerator is what internal/reasoners wraps as the `run_fix_generator`
// router reasoner; internal/phases drives it once per remediable finding through
// app.Call, never in-process, exactly as remediation_phase does in Python.
//
// # Shape of the phase
//
// One harness call per finding, with cwd=<fresh tempdir> and
// project_dir=<repo>, schema'd against RemediationSuggestion. There is no
// deterministic pre- or post-processing: the diffs, the breaking-change flag,
// the downtime estimate and the effort all come straight out of the model.
// Notably `finding_id` is a MANDATORY field of the prompt but is NOT stamped in
// by the Go or the Python code — the model is asked to echo it from
// {{FINDING_JSON}}.
//
// # Divergences from Python, in one place
//
//  1. model_dump(mode="json") vs model_dump(). This is the only agent in the
//     repo that asks for the JSON dump mode. For VerifiedFinding the two are
//     indistinguishable — every field is a str/int/float/bool, a str-Enum, a
//     list, a nested BaseModel or None, and json.dumps renders a str-Enum by its
//     value either way (verified against the interpreter). The Go port has one
//     dumper and therefore one behavior; a future VerifiedFinding field with a
//     type whose python and json modes differ (datetime, UUID, Decimal) would
//     need revisiting.
//  2. The json.dumps site goes through pyfmt.Dumps, whose documented deviations
//     are: `Any`-typed leaves that arrived as JSON numbers are float64 in Go, so
//     an integer renders as "1.0" where Python renders "1" (only reachable
//     through the DriftedResource nested in a VerifiedFinding); a Go map has no
//     insertion order, so a map[string]any inside a finding is dumped with
//     SORTED keys; and a NIL Go slice renders as `null` where pydantic's
//     default_factory=list guarantees `[]` — unreachable in the live DAG, where
//     every finding crossed a control-plane JSON boundary and was re-seeded by
//     VerifiedFinding.UnmarshalJSON. Struct field order — which is what
//     model_dump() order actually is — is preserved exactly.
//
// Everything else — the prompt bytes, the substitution ORDER, the tempdir
// prefix, the cwd/project_dir pair, the extract agent name ("FixGenerator") and
// the cleanup semantics — is byte-for-byte the Python behavior.
package remediate
