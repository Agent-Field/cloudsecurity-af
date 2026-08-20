package schemas

import (
	"encoding/json"
	"fmt"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// This file ports src/cloudsecurity_af/schemas/hunt.py — the HUNT phase enums
// and models.

// Confidence ports hunt.py `class Confidence(str, Enum)`: the confidence level
// for provisional findings.
type Confidence string

// The three confidence levels, values exactly as Python.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// AllConfidences lists every Confidence member in Python declaration order.
var AllConfidences = []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow}

// Valid reports whether c is one of the declared members.
func (c Confidence) Valid() bool {
	for _, v := range AllConfidences {
		if c == v {
			return true
		}
	}
	return false
}

// String returns the raw enum value.
func (c Confidence) String() string { return string(c) }

// ParseConfidence ports `Confidence(value)`: an unknown value is an error.
func ParseConfidence(v string) (Confidence, error) {
	c := Confidence(v)
	if !c.Valid() {
		return "", fmt.Errorf("schemas: %q is not a valid Confidence", v)
	}
	return c, nil
}

// UnmarshalJSON is strict, mirroring pydantic (verified: `confidence: "HIGH"`
// raises ValidationError — the enum is case-sensitive).
func (c *Confidence) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("schemas: Confidence must be a string: %w", err)
	}
	parsed, err := ParseConfidence(raw)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// HunterStrategy ports hunt.py `class HunterStrategy(str, Enum)`: the hunter
// specialization catalog.
//
// Python parity: this enum is a catalog only — RawFinding.hunter_strategy is
// typed `str`, not HunterStrategy, so no field validates against it.
type HunterStrategy string

// The seven hunter strategies, values exactly as Python.
const (
	HunterStrategyIAM        HunterStrategy = "iam"
	HunterStrategyNetwork    HunterStrategy = "network"
	HunterStrategyData       HunterStrategy = "data"
	HunterStrategySecrets    HunterStrategy = "secrets"
	HunterStrategyCompute    HunterStrategy = "compute"
	HunterStrategyLogging    HunterStrategy = "logging"
	HunterStrategyCompliance HunterStrategy = "compliance"
)

// AllHunterStrategies lists every HunterStrategy member in Python declaration order.
var AllHunterStrategies = []HunterStrategy{
	HunterStrategyIAM,
	HunterStrategyNetwork,
	HunterStrategyData,
	HunterStrategySecrets,
	HunterStrategyCompute,
	HunterStrategyLogging,
	HunterStrategyCompliance,
}

// Valid reports whether s is one of the declared members.
func (s HunterStrategy) Valid() bool {
	for _, v := range AllHunterStrategies {
		if s == v {
			return true
		}
	}
	return false
}

// String returns the raw enum value.
func (s HunterStrategy) String() string { return string(s) }

// ParseHunterStrategy ports `HunterStrategy(value)`.
func ParseHunterStrategy(v string) (HunterStrategy, error) {
	s := HunterStrategy(v)
	if !s.Valid() {
		return "", fmt.Errorf("schemas: %q is not a valid HunterStrategy", v)
	}
	return s, nil
}

// UnmarshalJSON is strict, mirroring pydantic.
func (s *HunterStrategy) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("schemas: HunterStrategy must be a string: %w", err)
	}
	parsed, err := ParseHunterStrategy(raw)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// FindingCategory ports hunt.py `class FindingCategory(str, Enum)`: the
// high-level finding category.
//
// Python parity: catalog only — RawFinding.category is typed `str`.
type FindingCategory string

// The thirteen finding categories, values exactly as Python.
const (
	FindingCategoryOverprivilege       FindingCategory = "overprivilege"
	FindingCategoryPublicExposure      FindingCategory = "public_exposure"
	FindingCategoryMissingEncryption   FindingCategory = "missing_encryption"
	FindingCategoryMissingLogging      FindingCategory = "missing_logging"
	FindingCategoryHardcodedSecret     FindingCategory = "hardcoded_secret"
	FindingCategoryInsecureDefault     FindingCategory = "insecure_default"
	FindingCategoryMissingMFA          FindingCategory = "missing_mfa"
	FindingCategoryDriftIntroduced     FindingCategory = "drift_introduced"
	FindingCategoryComplianceGap       FindingCategory = "compliance_gap"
	FindingCategoryDangerousTrust      FindingCategory = "dangerous_trust"
	FindingCategoryMissingBackup       FindingCategory = "missing_backup"
	FindingCategoryPrivilegedContainer FindingCategory = "privileged_container"
	FindingCategoryOutdatedRuntime     FindingCategory = "outdated_runtime"
)

// AllFindingCategories lists every FindingCategory member in Python declaration order.
var AllFindingCategories = []FindingCategory{
	FindingCategoryOverprivilege,
	FindingCategoryPublicExposure,
	FindingCategoryMissingEncryption,
	FindingCategoryMissingLogging,
	FindingCategoryHardcodedSecret,
	FindingCategoryInsecureDefault,
	FindingCategoryMissingMFA,
	FindingCategoryDriftIntroduced,
	FindingCategoryComplianceGap,
	FindingCategoryDangerousTrust,
	FindingCategoryMissingBackup,
	FindingCategoryPrivilegedContainer,
	FindingCategoryOutdatedRuntime,
}

// Valid reports whether c is one of the declared members.
func (c FindingCategory) Valid() bool {
	for _, v := range AllFindingCategories {
		if c == v {
			return true
		}
	}
	return false
}

// String returns the raw enum value.
func (c FindingCategory) String() string { return string(c) }

// ParseFindingCategory ports `FindingCategory(value)`.
func ParseFindingCategory(v string) (FindingCategory, error) {
	c := FindingCategory(v)
	if !c.Valid() {
		return "", fmt.Errorf("schemas: %q is not a valid FindingCategory", v)
	}
	return c, nil
}

// UnmarshalJSON is strict, mirroring pydantic.
func (c *FindingCategory) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("schemas: FindingCategory must be a string: %w", err)
	}
	parsed, err := ParseFindingCategory(raw)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// AffectedResource ports hunt.py AffectedResource: a specific resource attribute
// that is misconfigured.
type AffectedResource struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	// Attribute is the specific attribute that is misconfigured.
	Attribute        string `json:"attribute"`
	CurrentValue     string `json:"current_value"`
	RecommendedValue string `json:"recommended_value"`
}

// RawFinding ports hunt.py RawFinding: a potential misconfiguration or policy
// violation from a hunter.
type RawFinding struct {
	ID string `json:"id"`
	// HunterStrategy is one of iam | network | data | secrets | compute |
	// logging | compliance. Python types it `str`, not HunterStrategy.
	HunterStrategy string `json:"hunter_strategy"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	// Category is a finding category from the FindingCategory enum. Python
	// types it `str`, not FindingCategory.
	Category          string             `json:"category"`
	Resources         []AffectedResource `json:"resources"`
	EstimatedSeverity scoring.Severity   `json:"estimated_severity"`
	Confidence        Confidence         `json:"confidence"`
	IaCFile           string             `json:"iac_file"`
	IaCLine           int                `json:"iac_line"`
	ConfigSnippet     string             `json:"config_snippet"`
	// BenchmarkID is a CIS control ID, SOC2 control, etc.
	BenchmarkID *string `json:"benchmark_id"`
	Fingerprint string  `json:"fingerprint"`
}

// ForDedup ports RawFinding.for_dedup(): project the minimal fields needed for
// deduplication.
//
// Python parity: `estimated_severity=self.estimated_severity.value` — the view's
// field is a plain str, so the enum is unwrapped to its value.
func (f RawFinding) ForDedup() FindingForDedup {
	return FindingForDedup{
		ID:                f.ID,
		Fingerprint:       f.Fingerprint,
		Title:             f.Title,
		IaCFile:           f.IaCFile,
		IaCLine:           f.IaCLine,
		Category:          f.Category,
		HunterStrategy:    f.HunterStrategy,
		EstimatedSeverity: f.EstimatedSeverity.String(),
	}
}

// HuntResult ports hunt.py HuntResult: the deduplicated and correlated HUNT
// phase output.
type HuntResult struct {
	Findings            []RawFinding `json:"findings"`
	TotalRaw            int          `json:"total_raw"`
	DeduplicatedCount   int          `json:"deduplicated_count"`
	StrategiesRun       []string     `json:"strategies_run"`
	HuntDurationSeconds float64      `json:"hunt_duration_seconds"`
}
