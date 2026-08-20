package schemas

// This file ports the two pydantic BaseModels that
// src/cloudsecurity_af/agents/chain/path_constructor.py declares OUTSIDE the
// schemas/ package.
//
// They live here rather than in internal/agents/chain because they cross a JSON
// boundary: PathInvestigationPlan is the `schema=` argument of the CHAIN parent
// harness call (`await app.harness(prompt=parent_prompt,
// schema=PathInvestigationPlan, cwd=harness_cwd)`), so harnessx resolves its
// embedded pydantic schema fixture by the Go type NAME
// (testdata/schemas/PathInvestigationPlan.json) — the cross-agent contract in
// the shared preamble. The Go class names match Python exactly.
//
// NOTE for the internal/agents/chain owner: import these from internal/schemas;
// do not redeclare them.
//
// The three BaseModels in src/cloudsecurity_af/config.py (BudgetConfig,
// ScanConfig, AIIntegrationConfig) are deliberately NOT here — design §3 maps
// config.py to internal/config, and none of them is ever serialized across a
// reasoner boundary.

// ChildInvestigation ports path_constructor.py ChildInvestigation: one
// meta-prompted child investigation the parent CHAIN pass plans.
type ChildInvestigation struct {
	Title            string   `json:"title"`
	Rationale        string   `json:"rationale"`
	FindingsInvolved []string `json:"findings_involved"`
	ChildPrompt      string   `json:"child_prompt"`
}

// PathInvestigationPlan ports path_constructor.py PathInvestigationPlan: the
// parent harness call's structured output.
type PathInvestigationPlan struct {
	Investigations []ChildInvestigation `json:"investigations"`
}
