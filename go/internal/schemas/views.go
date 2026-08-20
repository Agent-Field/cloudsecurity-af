package schemas

// This file ports src/cloudsecurity_af/schemas/views.py — phase-boundary view
// models for context-specific data passing.
//
// These provide minimal projections of complex schemas for specific consumers,
// following the Composite Intelligence principle of contextual fidelity.

// FindingForDedup ports views.py FindingForDedup: the minimal fields needed for
// deduplication. Produced by RawFinding.ForDedup().
//
// Python parity: EstimatedSeverity is a plain `str` here, not a Severity enum —
// for_dedup() passes `self.estimated_severity.value`.
type FindingForDedup struct {
	ID                string `json:"id"`
	Fingerprint       string `json:"fingerprint"`
	Title             string `json:"title"`
	IaCFile           string `json:"iac_file"`
	IaCLine           int    `json:"iac_line"`
	Category          string `json:"category"`
	HunterStrategy    string `json:"hunter_strategy"`
	EstimatedSeverity string `json:"estimated_severity"`
}

// FindingForProver ports views.py FindingForProver: what the prover pipeline
// needs from a RawFinding plus its attack path.
type FindingForProver struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Category       string `json:"category"`
	HunterStrategy string `json:"hunter_strategy"`
	IaCFile        string `json:"iac_file"`
	IaCLine        int    `json:"iac_line"`
	ConfigSnippet  string `json:"config_snippet"`
	// ResourcesSummary is a natural language summary of affected resources.
	ResourcesSummary string `json:"resources_summary"`
	// AttackPathSummary is a natural language summary of the attack path (if any).
	AttackPathSummary string  `json:"attack_path_summary"`
	BenchmarkID       *string `json:"benchmark_id"`
}

// FindingForChain ports views.py FindingForChain: what the chain constructor
// needs from a RawFinding.
type FindingForChain struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	// Resources holds the resource IDs affected by this finding.
	Resources         []string `json:"resources"`
	EstimatedSeverity string   `json:"estimated_severity"`
	Confidence        string   `json:"confidence"`
}
