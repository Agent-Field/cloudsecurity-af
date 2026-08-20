package schemas

import "github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"

// This file ports src/cloudsecurity_af/schemas/chain.py — the CHAIN phase
// schemas. The CHAIN phase is CloudSecurity's key differentiator: it constructs
// multi-resource attack paths via meta-prompting.

// AttackStep ports chain.py AttackStep: one step in a multi-resource attack path.
type AttackStep struct {
	StepNumber   int    `json:"step_number"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	// Action is what the attacker does at this step.
	Action string `json:"action"`
	// PermissionUsed is the specific permission or config that enables this step.
	PermissionUsed string `json:"permission_used"`
	Description    string `json:"description"`
}

// BlastRadius ports chain.py BlastRadius: the impact assessment for a confirmed
// attack path.
type BlastRadius struct {
	DataStoresReachable []string `json:"data_stores_reachable"`
	ComputeReachable    []string `json:"compute_reachable"`
	EstimatedDataVolume *string  `json:"estimated_data_volume"`
	ServicesAffected    []string `json:"services_affected"`
}

// AttackPath ports chain.py AttackPath: a multi-resource attack path assembled
// from individual findings.
type AttackPath struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Steps       []AttackStep `json:"steps"`
	// EntryPoint is the public-facing resource where the attack begins.
	EntryPoint string `json:"entry_point"`
	// Target is what the attacker ultimately reaches.
	Target string `json:"target"`
	// FindingsInvolved holds the IDs of HUNT findings that compose this path.
	FindingsInvolved []string         `json:"findings_involved"`
	CombinedSeverity scoring.Severity `json:"combined_severity"`
	BlastRadius      BlastRadius      `json:"blast_radius"`
}

// ChainResult ports chain.py ChainResult: the complete CHAIN phase output.
type ChainResult struct {
	AttackPaths          []AttackPath `json:"attack_paths"`
	TotalPathsEvaluated  int          `json:"total_paths_evaluated"`
	ViablePaths          int          `json:"viable_paths"`
	ChainDurationSeconds float64      `json:"chain_duration_seconds"`
}
