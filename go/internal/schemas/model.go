package schemas

// model.go declares which of this package's structs are ports of a pydantic
// BaseModel.
//
// afx.Bind stands in for `Model.model_validate(payload)`, and pydantic's
// validation differs from a JSON round-trip in ways that only make sense for a
// MODEL: it coerces scalars in lax mode ("12" is a valid int) and it rejects an
// explicit `null` for a field that is not `X | None`. afx applies those rules
// to a struct that declares PydanticModel and to everything reachable from one
// — never to the reasoner INPUT structs, whose Python counterpart is a function
// signature validated by `Agent._validate_handler_input` (ported separately in
// afx/handlerinput.go, with a different and deliberately looser ladder).
//
// The list is exhaustive over the models in this package; model_test.go fails
// if a new exported model struct is added without a line here. Timestamp is
// NOT a model — it is the `datetime` scalar wrapper, an opaque leaf with its
// own UnmarshalJSON.

// --- recon.py ---------------------------------------------------------------

// PydanticModel marks Variable as a ported pydantic model.
func (Variable) PydanticModel() {}

// PydanticModel marks Output as a ported pydantic model.
func (Output) PydanticModel() {}

// PydanticModel marks ProviderConfig as a ported pydantic model.
func (ProviderConfig) PydanticModel() {}

// PydanticModel marks Module as a ported pydantic model.
func (Module) PydanticModel() {}

// PydanticModel marks Resource as a ported pydantic model.
func (Resource) PydanticModel() {}

// PydanticModel marks ResourceInventory as a ported pydantic model.
func (ResourceInventory) PydanticModel() {}

// PydanticModel marks ResourceGraph as a ported pydantic model.
func (ResourceGraph) PydanticModel() {}

// PydanticModel marks ConfigDiff as a ported pydantic model.
func (ConfigDiff) PydanticModel() {}

// PydanticModel marks DriftedResource as a ported pydantic model.
func (DriftedResource) PydanticModel() {}

// PydanticModel marks DriftReport as a ported pydantic model.
func (DriftReport) PydanticModel() {}

// PydanticModel marks ReconResult as a ported pydantic model.
func (ReconResult) PydanticModel() {}

// --- hunt.py ----------------------------------------------------------------

// PydanticModel marks AffectedResource as a ported pydantic model.
func (AffectedResource) PydanticModel() {}

// PydanticModel marks RawFinding as a ported pydantic model.
func (RawFinding) PydanticModel() {}

// PydanticModel marks HuntResult as a ported pydantic model.
func (HuntResult) PydanticModel() {}

// --- chain.py ---------------------------------------------------------------

// PydanticModel marks AttackStep as a ported pydantic model.
func (AttackStep) PydanticModel() {}

// PydanticModel marks BlastRadius as a ported pydantic model.
func (BlastRadius) PydanticModel() {}

// PydanticModel marks AttackPath as a ported pydantic model.
func (AttackPath) PydanticModel() {}

// PydanticModel marks ChainResult as a ported pydantic model.
func (ChainResult) PydanticModel() {}

// --- prove.py ---------------------------------------------------------------

// PydanticModel marks Proof as a ported pydantic model.
func (Proof) PydanticModel() {}

// PydanticModel marks IaCDiff as a ported pydantic model.
func (IaCDiff) PydanticModel() {}

// PydanticModel marks RemediationSuggestion as a ported pydantic model.
func (RemediationSuggestion) PydanticModel() {}

// PydanticModel marks VerifiedFinding as a ported pydantic model.
func (VerifiedFinding) PydanticModel() {}

// --- input.py ---------------------------------------------------------------

// PydanticModel marks CloudConfig as a ported pydantic model.
func (CloudConfig) PydanticModel() {}

// PydanticModel marks CloudSecurityInput as a ported pydantic model.
func (CloudSecurityInput) PydanticModel() {}

// NullableFields is CloudSecurityInput's `include_paths`, the port's ONE
// `X | None` field that is not a Go pointer: Python declares
// `include_paths: list[str] | None = None` (input.py:73) and treats None and []
// identically everywhere it reads it, so the port keeps a plain []string.
// pydantic accepts `{"include_paths": null}`; without this declaration the null
// rule would reject it.
func (CloudSecurityInput) NullableFields() []string { return []string{"include_paths"} }

// --- output.py --------------------------------------------------------------

// PydanticModel marks CloudSecurityScanResult as a ported pydantic model.
func (CloudSecurityScanResult) PydanticModel() {}

// PydanticModel marks ScanProgress as a ported pydantic model.
func (ScanProgress) PydanticModel() {}

// PydanticModel marks ScanMetrics as a ported pydantic model.
func (ScanMetrics) PydanticModel() {}

// --- views.py ---------------------------------------------------------------

// PydanticModel marks FindingForDedup as a ported pydantic model.
func (FindingForDedup) PydanticModel() {}

// PydanticModel marks FindingForProver as a ported pydantic model.
func (FindingForProver) PydanticModel() {}

// PydanticModel marks FindingForChain as a ported pydantic model.
func (FindingForChain) PydanticModel() {}

// --- agents/chain/path_constructor.py ---------------------------------------

// PydanticModel marks ChildInvestigation as a ported pydantic model.
func (ChildInvestigation) PydanticModel() {}

// PydanticModel marks PathInvestigationPlan as a ported pydantic model.
func (PathInvestigationPlan) PydanticModel() {}
