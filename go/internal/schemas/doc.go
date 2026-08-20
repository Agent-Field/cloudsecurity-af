// Package schemas ports every pydantic model CloudSecurity AF passes across a
// JSON boundary: src/cloudsecurity_af/schemas/{recon,hunt,chain,prove,input,
// output,views}.py, plus the two BaseModels declared inside
// src/cloudsecurity_af/agents/chain/path_constructor.py (ChildInvestigation,
// PathInvestigationPlan — see pathplan.go for why they live here).
//
// One Go file per Python module, same file name. Go struct name == pydantic
// class name, json tag == pydantic field name.
//
// # Import direction
//
// Python's schemas/*.py do `from ..scoring import Severity`, so this package
// imports internal/scoring and internal/scoring NEVER imports this package. The
// Severity / EvidenceMethod / Exposure enums stay in internal/scoring exactly as
// they stay in scoring.py; the enums that Python declares inside schemas/
// (Confidence, HunterStrategy, FindingCategory, Verdict, ProofMethod) live here.
//
// # Parity rules
//
//   - NO `omitempty` anywhere. Python reasoners return `model_dump()`, which
//     emits every declared field; the control plane sees all of them. Where a
//     call site needs `exclude_none=True` (the prove/remediation phases do),
//     that is applied by afx.DropNulls on the marshaled map, never by a struct
//     tag.
//   - `X | None` (Optional[X]) maps to a Go pointer so an unset value marshals
//     to JSON `null` exactly as Python does. The one exception is
//     `list[str] | None` (CloudSecurityInput.IncludePaths): a nil Go slice
//     already marshals as `null`, so a plain []string carries both states and
//     no extra indirection is needed.
//   - `dict[str, X]` with default_factory=dict maps to a Go map seeded to a
//     non-nil empty map, so it marshals as `{}` and never `null`.
//   - `Any` maps to Go `any` (marshals as `null` when nil, matching Python's
//     `None` default).
//
// # Default seeding (the pattern)
//
// Go's json.Unmarshal leaves an absent key at the Go zero value, whereas
// pydantic fills the declared default. Every struct that has at least one field
// whose pydantic default is not the Go zero value therefore gets BOTH:
//
//  1. an exported constructor `New<Model>()` returning the fully-defaulted value
//     — so a struct built in Go code (not decoded from JSON) serializes exactly
//     like `Model(**required_only)` does in Python; and
//  2. an `UnmarshalJSON` that assigns `New<Model>()` before decoding, so an
//     absent key keeps the pydantic default while a present key (even
//     `false`/`0`/`""`) overrides it.
//
// Both live in defaults.go, mirroring the pr-af port
// (pr-af/go/internal/schemas/defaults.go). The `type alias X` trick inside
// UnmarshalJSON strips X's methods so the inner json.Unmarshal does not recurse;
// nested field types keep their own UnmarshalJSON and re-seed themselves.
//
// A `New<Model>()` is provided for EVERY model, including the ones whose
// pydantic defaults are all Go zero values, so callers never have to know which
// is which. `default_factory=list` fields are always seeded to a non-nil empty
// slice, so an empty list marshals as `[]` and never `null`.
//
// `default_factory=lambda: str(uuid4())` fields (AttackPath.id, RawFinding.id,
// RawFinding.fingerprint, VerifiedFinding.id, VerifiedFinding.fingerprint) are
// seeded with a fresh RFC 4122 v4 string by NewUUID4 (uuid.go, crypto/rand — no
// third-party dependency). Both the constructor and UnmarshalJSON generate one,
// matching pydantic, which calls the default_factory on every model_validate
// that omits the key.
//
// # Strict enums
//
// Every enum type here (and in internal/scoring) has a strict UnmarshalJSON:
// an unknown member, a null, or a non-string is a decode error, exactly as
// pydantic raises ValidationError. Verified against the interpreter:
// `RawFinding.model_validate({..., "estimated_severity": "bogus"})` and
// `{"estimated_severity": None}` both raise.
//
// # Known Python bug reproduced, not fixed: ReconResult
//
// `ReconResult.inventory` and `.resource_graph` declare
// `default_factory=ResourceInventory` / `ResourceGraph`, but both of those
// models have a REQUIRED field (`inventory_saved_path` / `graph_saved_path`), so
// the factories raise ValidationError — `ReconResult()` with no arguments is
// unconstructible in Python today. Go cannot raise from a struct literal, so
// NewReconResult() seeds the two sub-models with their own constructors (giving
// `inventory_saved_path: ""`, `iac_type: "terraform"`, …). The observable JSON
// matches `ReconResult(inventory=ResourceInventory(inventory_saved_path=""),
// resource_graph=ResourceGraph(graph_saved_path=""))`, which is what
// scripts/gen_model_keys.py pins. reasoners/phases.py always passes both
// explicitly, so the live path is unaffected.
//
// # Validation
//
// The Python schemas declare no numeric (ge/le/gt/lt) or length constraints and
// no @field_validator / @model_validator, so there is nothing for a Validate()
// method to enforce beyond required-field presence, which the Go type system
// cannot express. No Validate() methods are defined; the strict enum
// UnmarshalJSON is the only runtime validation this package performs.
//
// # Ground truth
//
// testdata/model_keys.json is generated by go/scripts/gen_model_keys.py against
// the venv interpreter and holds, for every model, the exact key list and the
// exact `jsonable_encoder(model_dump())` default vector. parity_test.go asserts
// the Go constructors reproduce both.
package schemas
