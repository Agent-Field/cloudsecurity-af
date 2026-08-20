package schemas

import (
	"encoding/json"
	"fmt"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// This file ports src/cloudsecurity_af/schemas/prove.py — the PROVE phase enums
// and models.

// Verdict ports prove.py `class Verdict(str, Enum)`: exploitability verdict
// semantics.
type Verdict string

// The four verdicts, values exactly as Python.
const (
	VerdictConfirmed      Verdict = "confirmed"
	VerdictLikely         Verdict = "likely"
	VerdictInconclusive   Verdict = "inconclusive"
	VerdictNotExploitable Verdict = "not_exploitable"
)

// AllVerdicts lists every Verdict member in Python declaration order.
var AllVerdicts = []Verdict{VerdictConfirmed, VerdictLikely, VerdictInconclusive, VerdictNotExploitable}

// Valid reports whether v is one of the declared members.
func (v Verdict) Valid() bool {
	for _, m := range AllVerdicts {
		if v == m {
			return true
		}
	}
	return false
}

// String returns the raw enum value.
func (v Verdict) String() string { return string(v) }

// ParseVerdict ports `Verdict(value)`.
func ParseVerdict(v string) (Verdict, error) {
	m := Verdict(v)
	if !m.Valid() {
		return "", fmt.Errorf("schemas: %q is not a valid Verdict", v)
	}
	return m, nil
}

// UnmarshalJSON is strict, mirroring pydantic.
func (v *Verdict) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("schemas: Verdict must be a string: %w", err)
	}
	parsed, err := ParseVerdict(raw)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

// ProofMethod ports prove.py `class ProofMethod(str, Enum)`: the verification
// method used to reach the verdict.
type ProofMethod string

// The four proof methods, values exactly as Python.
const (
	ProofMethodStaticAnalysis      ProofMethod = "static_analysis"
	ProofMethodLiveAPIVerification ProofMethod = "live_api_verification"
	ProofMethodIAMSimulation       ProofMethod = "iam_simulation"
	ProofMethodDriftComparison     ProofMethod = "drift_comparison"
)

// AllProofMethods lists every ProofMethod member in Python declaration order.
var AllProofMethods = []ProofMethod{
	ProofMethodStaticAnalysis,
	ProofMethodLiveAPIVerification,
	ProofMethodIAMSimulation,
	ProofMethodDriftComparison,
}

// Valid reports whether m is one of the declared members.
func (m ProofMethod) Valid() bool {
	for _, v := range AllProofMethods {
		if m == v {
			return true
		}
	}
	return false
}

// String returns the raw enum value.
func (m ProofMethod) String() string { return string(m) }

// ParseProofMethod ports `ProofMethod(value)`.
func ParseProofMethod(v string) (ProofMethod, error) {
	m := ProofMethod(v)
	if !m.Valid() {
		return "", fmt.Errorf("schemas: %q is not a valid ProofMethod", v)
	}
	return m, nil
}

// UnmarshalJSON is strict, mirroring pydantic.
func (m *ProofMethod) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("schemas: ProofMethod must be a string: %w", err)
	}
	parsed, err := ParseProofMethod(raw)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

// Proof ports prove.py Proof: the evidence supporting a verdict.
type Proof struct {
	Method   ProofMethod `json:"method"`
	Evidence []string    `json:"evidence"`
	// ScriptsExecuted holds the actual commands/scripts the harness ran.
	ScriptsExecuted []string `json:"scripts_executed"`
	// VerificationTier is one of static | live.
	VerificationTier string `json:"verification_tier"`
}

// IaCDiff ports prove.py IaCDiff: a unified diff patch for remediation.
type IaCDiff struct {
	FilePath      string `json:"file_path"`
	OriginalLines string `json:"original_lines"`
	PatchedLines  string `json:"patched_lines"`
	StartLine     int    `json:"start_line"`
	EndLine       int    `json:"end_line"`
}

// RemediationSuggestion ports prove.py RemediationSuggestion: an actionable IaC
// fix for a finding.
type RemediationSuggestion struct {
	FindingID      string    `json:"finding_id"`
	Description    string    `json:"description"`
	Diffs          []IaCDiff `json:"diffs"`
	BreakingChange bool      `json:"breaking_change"`
	// DowntimeEstimate is one of none | seconds | minutes |
	// requires_maintenance_window.
	DowntimeEstimate *string `json:"downtime_estimate"`
	// Effort is one of trivial | moderate | significant.
	Effort                string   `json:"effort"`
	AlternativeApproaches []string `json:"alternative_approaches"`
}

// VerifiedFinding ports prove.py VerifiedFinding: a finding fully assessed by
// the PROVE phase.
type VerifiedFinding struct {
	ID         string             `json:"id"`
	Title      string             `json:"title"`
	Verdict    Verdict            `json:"verdict"`
	Severity   scoring.Severity   `json:"severity"`
	Category   string             `json:"category"`
	Resources  []AffectedResource `json:"resources"`
	AttackPath *AttackPath        `json:"attack_path"`
	Drift      *DriftedResource   `json:"drift"`
	Proof      Proof              `json:"proof"`
	// ComplianceMappings holds CIS control IDs, SOC2 controls, etc.
	ComplianceMappings []string               `json:"compliance_mappings"`
	RiskScore          float64                `json:"risk_score"`
	Remediation        *RemediationSuggestion `json:"remediation"`

	// SARIF integration.
	SARIFRuleID           string  `json:"sarif_rule_id"`
	SARIFSecuritySeverity float64 `json:"sarif_security_severity"`

	// Traceability.
	IaCFile        string  `json:"iac_file"`
	IaCLine        int     `json:"iac_line"`
	ConfigSnippet  string  `json:"config_snippet"`
	Description    string  `json:"description"`
	Fingerprint    string  `json:"fingerprint"`
	HunterStrategy string  `json:"hunter_strategy"`
	DropReason     *string `json:"drop_reason"`
}
