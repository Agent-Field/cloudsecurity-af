package schemas

import "github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"

// This file ports src/cloudsecurity_af/schemas/output.py — the scan output and
// orchestration progress/metrics models.

// CloudSecurityScanResult ports output.py CloudSecurityScanResult: the top-level
// CloudSecurity scan output.
type CloudSecurityScanResult struct {
	Repository string  `json:"repository"`
	CommitSHA  string  `json:"commit_sha"`
	Branch     *string `json:"branch"`
	// Timestamp is a pydantic `datetime` — see timestamp.go for the exact wire
	// format (`datetime.isoformat()` via FastAPI's jsonable_encoder).
	Timestamp    Timestamp `json:"timestamp"`
	DepthProfile string    `json:"depth_profile"`
	// Tier is 1 = static, 2 = live, 3 = deep.
	Tier              int      `json:"tier"`
	ProvidersDetected []string `json:"providers_detected"`

	// Findings.
	Findings    []VerifiedFinding `json:"findings"`
	AttackPaths []AttackPath      `json:"attack_paths"`

	// Counts.
	TotalResourcesScanned int            `json:"total_resources_scanned"`
	TotalRawFindings      int            `json:"total_raw_findings"`
	Confirmed             int            `json:"confirmed"`
	Likely                int            `json:"likely"`
	Inconclusive          int            `json:"inconclusive"`
	NotExploitable        int            `json:"not_exploitable"`
	NoiseReductionPct     float64        `json:"noise_reduction_pct"`
	BySeverity            map[string]int `json:"by_severity"`

	// Drift (Tier 2+).
	DriftResources    int `json:"drift_resources"`
	ShadowITResources int `json:"shadow_it_resources"`

	// Compliance.
	ComplianceFrameworksChecked []string `json:"compliance_frameworks_checked"`
	ComplianceGaps              []string `json:"compliance_gaps"`

	// Strategies.
	StrategiesUsed []string `json:"strategies_used"`

	// Performance.
	DurationSeconds  float64            `json:"duration_seconds"`
	AgentInvocations int                `json:"agent_invocations"`
	CostUSD          float64            `json:"cost_usd"`
	CostBreakdown    map[string]float64 `json:"cost_breakdown"`

	// Metadata.
	Metadata map[string]any `json:"metadata"`
	SARIF    string         `json:"sarif"`
}

// DictFieldOrder implements afx.DictFieldOrder: it names the two map-typed
// fields whose Python dict insertion order is fixed by orchestrator.py's
// seeding, so the `scan` / `prove` reply keeps Python's key order instead of
// the alphabetical order a Go map renders with.
//
// Python (src/cloudsecurity_af/app.py:234 `return result.model_dump()`) puts
//
//	"by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
//	"cost_breakdown": {"recon": 0.0, "hunt": 0.0, "chain": 0.0, "prove": 0.0, "remediate": 0.0}
//
// on the wire; sorting them instead yields critical/high/info/low/medium and
// chain/hunt/prove/recon/remediate.
func (CloudSecurityScanResult) DictFieldOrder() map[string][]string {
	return map[string][]string{
		"by_severity":    BySeverityOrder(),
		"cost_breakdown": CostBreakdownOrder,
	}
}

// ScanProgress ports output.py ScanProgress: an orchestrator phase progress
// event.
//
// Python parity: every field is required (no defaults), and orchestrator.py
// builds a ScanProgress in _emit_progress but never emits it as a note — the
// Go orch port keeps that a no-op builder too.
type ScanProgress struct {
	Phase                     string  `json:"phase"`
	PhaseProgress             float64 `json:"phase_progress"`
	AgentsTotal               int     `json:"agents_total"`
	AgentsCompleted           int     `json:"agents_completed"`
	AgentsRunning             int     `json:"agents_running"`
	FindingsSoFar             int     `json:"findings_so_far"`
	ElapsedSeconds            float64 `json:"elapsed_seconds"`
	EstimatedRemainingSeconds float64 `json:"estimated_remaining_seconds"`
	CostSoFarUSD              float64 `json:"cost_so_far_usd"`
}

// ScanMetrics ports output.py ScanMetrics: run-level performance and budget
// metrics.
type ScanMetrics struct {
	DurationSeconds     float64            `json:"duration_seconds"`
	AgentInvocations    int                `json:"agent_invocations"`
	CostUSD             float64            `json:"cost_usd"`
	CostBreakdown       map[string]float64 `json:"cost_breakdown"`
	BudgetExhausted     bool               `json:"budget_exhausted"`
	FindingsNotVerified int                `json:"findings_not_verified"`
}

// CostBreakdownOrder is the INSERTION order of the `cost_breakdown` dict.
//
// src/cloudsecurity_af/orchestrator.py:54,67:
//
//	_PHASE_ORDER = ("recon", "hunt", "chain", "prove", "remediate")
//	self.cost_breakdown = {phase: 0.0 for phase in self._PHASE_ORDER}
//
// The dict is seeded from that tuple and never gains a key on the live path
// (_register_cost only mutates existing entries), so a Python dict — and every
// artifact that walks it with `.items()` — always reads recon, hunt, chain,
// prove, remediate. A Go map has no order, so every renderer of this field
// takes it from here instead of sorting.
var CostBreakdownOrder = []string{"recon", "hunt", "chain", "prove", "remediate"}

// BySeverityOrder is the INSERTION order of the `by_severity` dict.
//
// src/cloudsecurity_af/orchestrator.py:165:
//
//	severity_counts = {s.value: 0 for s in Severity}
//
// i.e. the Severity enum's declaration order — critical, high, medium, low,
// info — never the alphabetical critical, high, info, low, medium.
func BySeverityOrder() []string {
	out := make([]string, 0, len(scoring.AllSeverities))
	for _, s := range scoring.AllSeverities {
		out = append(out, s.String())
	}
	return out
}
