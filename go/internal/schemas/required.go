package schemas

// required.go transcribes, per model,
//
//	[name for name, f in Model.model_fields.items() if f.is_required()]
//
// i.e. the fields a pydantic model has NO default for, which
// `Model.model_validate(payload)` raises `ValidationError(type=missing)` on
// when the payload omits them. afx.Bind consults these lists so that every
// ported `model_validate` call raises where Python raises instead of quietly
// producing a zero-valued model — see internal/afx/required.go for why that
// matters on the recon_phase and prove_phase boundaries.
//
// The lists were read off the live models under the repo venv, and
// required_test.go re-checks the eight models that have a committed pydantic
// schema fixture (internal/harnessx/testdata/schemas/*.json) against that
// fixture's `required` array — so a schema change in Python that regenerates
// the fixtures fails the build here rather than silently loosening validation.
//
// Models whose every field has a default (DriftReport, HuntResult, ChainResult,
// ReconResult, Proof, BlastRadius, CloudConfig, …) declare no method: pydantic
// accepts `Model.model_validate({})` for them, and so must the port.

// --- input.py ---------------------------------------------------------------

// RequiredFields is CloudSecurityInput's `repo_url`.
func (CloudSecurityInput) RequiredFields() []string { return []string{"repo_url"} }

// --- recon.py ---------------------------------------------------------------

// RequiredFields is Variable's `name`.
func (Variable) RequiredFields() []string { return []string{"name"} }

// RequiredFields is Output's `name`.
func (Output) RequiredFields() []string { return []string{"name"} }

// RequiredFields is ProviderConfig's `name`.
func (ProviderConfig) RequiredFields() []string { return []string{"name"} }

// RequiredFields is Module's `name` and `source`.
func (Module) RequiredFields() []string { return []string{"name", "source"} }

// RequiredFields is Resource's five required fields.
func (Resource) RequiredFields() []string {
	return []string{"id", "type", "name", "provider", "file_path"}
}

// RequiredFields is ResourceInventory's `inventory_saved_path` — the field
// recon_phase's first model_validate raises on.
func (ResourceInventory) RequiredFields() []string { return []string{"inventory_saved_path"} }

// RequiredFields is ResourceGraph's `graph_saved_path`.
func (ResourceGraph) RequiredFields() []string { return []string{"graph_saved_path"} }

// RequiredFields is ConfigDiff's `attribute`.
func (ConfigDiff) RequiredFields() []string { return []string{"attribute"} }

// RequiredFields is DriftedResource's `resource_id` and `resource_type`.
func (DriftedResource) RequiredFields() []string { return []string{"resource_id", "resource_type"} }

// --- hunt.py ----------------------------------------------------------------

// RequiredFields is AffectedResource's three required fields.
func (AffectedResource) RequiredFields() []string {
	return []string{"resource_id", "resource_type", "attribute"}
}

// RequiredFields is RawFinding's four required fields.
func (RawFinding) RequiredFields() []string {
	return []string{"hunter_strategy", "title", "description", "category"}
}

// --- chain.py ---------------------------------------------------------------

// RequiredFields is AttackStep's five required fields.
func (AttackStep) RequiredFields() []string {
	return []string{"step_number", "resource_id", "resource_type", "action", "permission_used"}
}

// RequiredFields is AttackPath's four required fields.
func (AttackPath) RequiredFields() []string {
	return []string{"title", "description", "entry_point", "target"}
}

// --- prove.py ---------------------------------------------------------------

// RequiredFields is IaCDiff's three required fields.
func (IaCDiff) RequiredFields() []string {
	return []string{"file_path", "original_lines", "patched_lines"}
}

// RequiredFields is RemediationSuggestion's `description`.
func (RemediationSuggestion) RequiredFields() []string { return []string{"description"} }

// RequiredFields is VerifiedFinding's four required fields — the ones
// prove_phase's `_fallback_verified(finding, "Schema parse failed: ...")`
// branch depends on being raised for.
func (VerifiedFinding) RequiredFields() []string {
	return []string{"title", "verdict", "severity", "category"}
}

// --- output.py --------------------------------------------------------------

// RequiredFields is CloudSecurityScanResult's five required fields.
func (CloudSecurityScanResult) RequiredFields() []string {
	return []string{"repository", "commit_sha", "timestamp", "depth_profile", "tier"}
}

// RequiredFields is ScanProgress's nine required fields.
func (ScanProgress) RequiredFields() []string {
	return []string{
		"phase", "phase_progress", "agents_total", "agents_completed", "agents_running",
		"findings_so_far", "elapsed_seconds", "estimated_remaining_seconds", "cost_so_far_usd",
	}
}

// RequiredFields is ScanMetrics's three required fields.
func (ScanMetrics) RequiredFields() []string {
	return []string{"duration_seconds", "agent_invocations", "cost_usd"}
}

// --- views.py ---------------------------------------------------------------

// RequiredFields is FindingForDedup's eight required fields.
func (FindingForDedup) RequiredFields() []string {
	return []string{"id", "fingerprint", "title", "iac_file", "iac_line", "category", "hunter_strategy", "estimated_severity"}
}

// RequiredFields is FindingForProver's eight required fields.
func (FindingForProver) RequiredFields() []string {
	return []string{"id", "title", "description", "category", "hunter_strategy", "iac_file", "iac_line", "config_snippet"}
}

// RequiredFields is FindingForChain's four required fields.
func (FindingForChain) RequiredFields() []string {
	return []string{"id", "title", "description", "category"}
}

// --- agents/chain/path_constructor.py ---------------------------------------
//
// PathInvestigationPlan and ChildInvestigation are declared next to the CHAIN
// parent agent in Python; the port keeps them in schemas (DESIGN §2c).

// RequiredFields is ChildInvestigation's `title` and `child_prompt`.
func (ChildInvestigation) RequiredFields() []string { return []string{"title", "child_prompt"} }
