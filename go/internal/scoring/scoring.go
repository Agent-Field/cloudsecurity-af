// Package scoring is the deterministic risk-scoring engine for CloudSecurity AF —
// a 1:1 port of src/cloudsecurity_af/scoring.py.
//
// It owns the three vocabularies the rest of the node scores against (Severity,
// EvidenceMethod, Exposure), the weight/multiplier tables, the CIS benchmark
// severity floors, and the two pure functions the orchestrator calls
// (ComputeRiskScore, ApplyBenchmarkSeverityFloor) plus SeverityLabelFromScore.
//
// Import direction (mirrors Python): schemas/*.py does `from ..scoring import
// Severity`, so internal/schemas imports internal/scoring and NEVER the reverse.
// Keeping Severity here — rather than in internal/schemas — is what makes that
// acyclic.
//
// Parity notes:
//   - Python `round(x, 2)` is round-half-to-even on the true binary value.
//     Go's math.Round is half-away-from-zero and would diverge (2.125 -> 2.13
//     instead of 2.12), so ComputeRiskScore delegates to pyfmt.Round.
//   - Python's `SEVERITY_WEIGHTS[severity.value]` / `EVIDENCE_MULTIPLIERS[m]` /
//     `EXPOSURE_MULTIPLIERS[e]` raise KeyError on an unknown member. Go map
//     lookups yield the zero value instead, so a hand-built Severity("bogus")
//     scores 0.0 here where Python would raise. The enum types are closed
//     (Valid()/ParseX + a strict UnmarshalJSON), so this is unreachable for any
//     value that came in over the wire; it is documented rather than papered
//     over with a panic.
package scoring

import (
	"encoding/json"
	"fmt"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// Severity ports scoring.py `class Severity(str, Enum)`.
type Severity string

// The five severity members, values exactly as Python.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AllSeverities lists every Severity member in Python declaration order.
var AllSeverities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

// Valid reports whether s is one of the declared members.
func (s Severity) Valid() bool {
	for _, v := range AllSeverities {
		if s == v {
			return true
		}
	}
	return false
}

// String returns the raw enum value ("critical", …), matching Python's
// `Severity.CRITICAL.value` (the member is a str subclass).
func (s Severity) String() string { return string(s) }

// ParseSeverity ports `Severity(value)`: an unknown value is an error, exactly
// as pydantic/enum raises ValueError.
func ParseSeverity(v string) (Severity, error) {
	s := Severity(v)
	if !s.Valid() {
		return "", fmt.Errorf("scoring: %q is not a valid Severity", v)
	}
	return s, nil
}

// UnmarshalJSON is strict, mirroring pydantic: an unknown value (or null, or a
// non-string) is a validation error rather than a silent coercion. This is a
// deliberate difference from pr-af, whose Severity carries a BeforeValidator.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("scoring: Severity must be a string: %w", err)
	}
	parsed, err := ParseSeverity(raw)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// EvidenceMethod ports scoring.py `class EvidenceMethod(str, Enum)`.
type EvidenceMethod string

// The six evidence methods, values exactly as Python.
const (
	EvidenceMethodLiveVerified         EvidenceMethod = "live_verified"
	EvidenceMethodIAMSimulated         EvidenceMethod = "iam_simulated"
	EvidenceMethodDriftConfirmed       EvidenceMethod = "drift_confirmed"
	EvidenceMethodStaticGraphConfirmed EvidenceMethod = "static_graph_confirmed"
	EvidenceMethodStaticConfigMatch    EvidenceMethod = "static_config_match"
	EvidenceMethodHeuristicMatch       EvidenceMethod = "heuristic_match"
)

// AllEvidenceMethods lists every EvidenceMethod member in Python declaration order.
var AllEvidenceMethods = []EvidenceMethod{
	EvidenceMethodLiveVerified,
	EvidenceMethodIAMSimulated,
	EvidenceMethodDriftConfirmed,
	EvidenceMethodStaticGraphConfirmed,
	EvidenceMethodStaticConfigMatch,
	EvidenceMethodHeuristicMatch,
}

// Valid reports whether m is one of the declared members.
func (m EvidenceMethod) Valid() bool {
	for _, v := range AllEvidenceMethods {
		if m == v {
			return true
		}
	}
	return false
}

// String returns the raw enum value.
func (m EvidenceMethod) String() string { return string(m) }

// ParseEvidenceMethod ports `EvidenceMethod(value)`.
func ParseEvidenceMethod(v string) (EvidenceMethod, error) {
	m := EvidenceMethod(v)
	if !m.Valid() {
		return "", fmt.Errorf("scoring: %q is not a valid EvidenceMethod", v)
	}
	return m, nil
}

// UnmarshalJSON is strict, mirroring pydantic.
func (m *EvidenceMethod) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("scoring: EvidenceMethod must be a string: %w", err)
	}
	parsed, err := ParseEvidenceMethod(raw)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

// Exposure ports scoring.py `class Exposure(str, Enum)`.
type Exposure string

// The five exposure levels, values exactly as Python.
const (
	ExposureInternetFacing  Exposure = "internet_facing"
	ExposureVPCInternal     Exposure = "vpc_internal"
	ExposurePrivateSubnet   Exposure = "private_subnet"
	ExposureRequiresIAMAuth Exposure = "requires_iam_auth"
	ExposureRequiresAdmin   Exposure = "requires_admin"
)

// AllExposures lists every Exposure member in Python declaration order.
var AllExposures = []Exposure{
	ExposureInternetFacing,
	ExposureVPCInternal,
	ExposurePrivateSubnet,
	ExposureRequiresIAMAuth,
	ExposureRequiresAdmin,
}

// Valid reports whether e is one of the declared members.
func (e Exposure) Valid() bool {
	for _, v := range AllExposures {
		if e == v {
			return true
		}
	}
	return false
}

// String returns the raw enum value.
func (e Exposure) String() string { return string(e) }

// ParseExposure ports `Exposure(value)`.
func ParseExposure(v string) (Exposure, error) {
	e := Exposure(v)
	if !e.Valid() {
		return "", fmt.Errorf("scoring: %q is not a valid Exposure", v)
	}
	return e, nil
}

// UnmarshalJSON is strict, mirroring pydantic.
func (e *Exposure) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("scoring: Exposure must be a string: %w", err)
	}
	parsed, err := ParseExposure(raw)
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}

// SeverityWeights ports scoring.py SEVERITY_WEIGHTS. Keyed by the severity
// *value* string (Python indexes it with `severity.value`).
var SeverityWeights = map[string]float64{
	"critical": 10.0,
	"high":     8.0,
	"medium":   5.0,
	"low":      3.0,
	"info":     1.0,
}

// EvidenceMultipliers ports scoring.py EVIDENCE_MULTIPLIERS.
var EvidenceMultipliers = map[EvidenceMethod]float64{
	EvidenceMethodLiveVerified:         1.0,
	EvidenceMethodIAMSimulated:         0.9,
	EvidenceMethodDriftConfirmed:       0.85,
	EvidenceMethodStaticGraphConfirmed: 0.7,
	EvidenceMethodStaticConfigMatch:    0.5,
	EvidenceMethodHeuristicMatch:       0.2,
}

// ExposureMultipliers ports scoring.py EXPOSURE_MULTIPLIERS.
var ExposureMultipliers = map[Exposure]float64{
	ExposureInternetFacing:  1.0,
	ExposureVPCInternal:     0.7,
	ExposurePrivateSubnet:   0.5,
	ExposureRequiresIAMAuth: 0.4,
	ExposureRequiresAdmin:   0.2,
}

// benchmarkSeverityFloors ports scoring.py _BENCHMARK_SEVERITY_FLOORS — CIS AWS
// controls that must never be reported below a given severity. Unexported,
// matching the Python leading underscore.
var benchmarkSeverityFloors = map[string]string{
	// CIS AWS controls that should never be reported below certain severity
	"CIS-AWS-1.4":   "critical", // root account MFA
	"CIS-AWS-1.5":   "critical", // root account access keys
	"CIS-AWS-2.1.1": "high",     // S3 bucket public access
	"CIS-AWS-2.1.2": "high",     // S3 bucket encryption
	"CIS-AWS-2.2.1": "high",     // EBS encryption
	"CIS-AWS-3.1":   "high",     // CloudTrail enabled
	"CIS-AWS-4.1":   "high",     // security group ingress 0.0.0.0/0
	"CIS-AWS-5.1":   "high",     // VPC flow logs
}

// severityOrder ports scoring.py _SEVERITY_ORDER — the rank used to decide
// whether a floor is an upgrade.
var severityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// ApplyBenchmarkSeverityFloor ports scoring.py apply_benchmark_severity_floor.
//
// benchmarkID is `str | None`; a nil pointer is Python's None and returns
// currentSeverity untouched, as does an ID with no floor entry. The floor only
// ever *raises* severity — Python parity: the comparison is strictly greater, so
// an equal or lower floor is a no-op.
func ApplyBenchmarkSeverityFloor(benchmarkID *string, currentSeverity Severity) Severity {
	if benchmarkID == nil {
		return currentSeverity
	}
	floorLabel, ok := benchmarkSeverityFloors[*benchmarkID]
	if !ok {
		return currentSeverity
	}
	// Python parity: `_SEVERITY_ORDER.get(label, 0)` — an unknown label ranks 0.
	if severityOrder[floorLabel] > severityOrder[currentSeverity.String()] {
		return Severity(floorLabel)
	}
	return currentSeverity
}

// ComputeRiskScore ports scoring.py compute_risk_score.
//
//	score = severity_weight * evidence_mult * exposure_mult * path_bonus * drift_bonus
//	return round(min(max(score, 0.0), 10.0), 2)
//
// hasAttackPath and hasDrift are keyword-only in Python (`*, has_attack_path,
// has_drift`); Go takes them positionally in the same order.
func ComputeRiskScore(severity Severity, evidenceMethod EvidenceMethod, exposure Exposure, hasAttackPath, hasDrift bool) float64 {
	severityWeight := SeverityWeights[severity.String()]
	evidenceMult := EvidenceMultipliers[evidenceMethod]
	exposureMult := ExposureMultipliers[exposure]
	pathBonus := 1.0
	if hasAttackPath {
		pathBonus = 2.0
	}
	driftBonus := 1.0
	if hasDrift {
		driftBonus = 1.3
	}

	score := severityWeight * evidenceMult * exposureMult * pathBonus * driftBonus
	if score < 0.0 {
		score = 0.0
	}
	if score > 10.0 {
		score = 10.0
	}
	return pyfmt.Round(score, 2)
}

// SeverityLabelFromScore ports scoring.py severity_label_from_score. It returns
// a plain string (Python returns str, not Severity) so callers must convert
// explicitly if they want the enum.
func SeverityLabelFromScore(score float64) string {
	if score >= 9.0 {
		return "critical"
	}
	if score >= 7.0 {
		return "high"
	}
	if score >= 4.0 {
		return "medium"
	}
	if score >= 1.0 {
		return "low"
	}
	return "info"
}
