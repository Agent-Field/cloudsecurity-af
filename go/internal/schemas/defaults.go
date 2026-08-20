package schemas

import (
	"bytes"
	"encoding/json"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// This file implements the default-seeding pattern documented in doc.go.
//
// Every model gets an exported New<Model>() returning the value a Python
// `Model(**required_only)` produces — non-zero scalar defaults filled in,
// default_factory=list fields seeded to non-nil empty slices (so they marshal as
// `[]`, never `null`), default_factory=dict fields seeded to non-nil empty maps,
// and uuid4 default_factory fields seeded with a fresh NewUUID4().
//
// Models whose defaults are all Go zero values still get a constructor (so
// callers never have to know which is which) but no UnmarshalJSON — there is
// nothing to seed and the extra method would only cost an allocation.
//
// Where a model DOES need seeding, its UnmarshalJSON assigns the constructor's
// value before decoding. The `type alias X` trick strips X's methods (including
// UnmarshalJSON) so the inner json.Unmarshal does not recurse; nested field
// types keep their own UnmarshalJSON and re-seed themselves.
//
// Ordering below follows the Python modules: recon, hunt, chain, prove, input,
// output, views, pathplan.

// decodeSeeded is the inner decode every default-seeding UnmarshalJSON runs
// after it has assigned the constructor's value.
//
// It is a UseNumber decode, not json.Unmarshal, because several of these models
// carry free-form `Any`-typed fields — DriftedResource.iac_config /
// live_config are `dict[str, Any]` and ConfigDiff.iac_value / live_value are
// `Any` — and plain encoding/json decodes every JSON number landing in such a
// field as float64. Python keeps `{"port": 5432}` an INT all the way to
// json.dumps, so a float64 would re-render as `5432.0` in the CHAIN parent
// prompt ({{DRIFT_REPORT_JSON}}), in the fix-generator prompt
// ({{FINDING_JSON}}), in .cloudsecurity/checkpoint-recon.json and in the final
// scan result. json.Number keeps the literal, and both encoding/json and
// pyfmt.Dumps re-emit it verbatim.
//
// Typed fields are unaffected: UseNumber only changes decoding into `any`.
func decodeSeeded(b []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(dest)
}

// --- recon.go ---------------------------------------------------------------

// NewVariable returns Variable's pydantic defaults (all Go zero / nil).
func NewVariable() Variable { return Variable{} }

// NewOutput returns Output's pydantic defaults (all Go zero / nil).
func NewOutput() Output { return Output{} }

// NewProviderConfig returns ProviderConfig's pydantic defaults (all Go zero / nil).
func NewProviderConfig() ProviderConfig { return ProviderConfig{} }

// NewModule returns Module's pydantic defaults (all Go zero / nil).
func NewModule() Module { return Module{} }

// NewResource seeds Resource's config={} / references=[] / referenced_by=[].
func NewResource() Resource {
	return Resource{
		Config:       map[string]any{},
		References:   []string{},
		ReferencedBy: []string{},
	}
}

// UnmarshalJSON seeds Resource's dict/list defaults.
func (r *Resource) UnmarshalJSON(b []byte) error {
	*r = NewResource()
	type alias Resource
	return decodeSeeded(b, (*alias)(r))
}

// NewResourceInventory seeds ResourceInventory.iac_type="terraform".
func NewResourceInventory() ResourceInventory {
	return ResourceInventory{IaCType: "terraform"}
}

// UnmarshalJSON seeds ResourceInventory.iac_type="terraform".
func (i *ResourceInventory) UnmarshalJSON(b []byte) error {
	*i = NewResourceInventory()
	type alias ResourceInventory
	return decodeSeeded(b, (*alias)(i))
}

// NewResourceGraph returns ResourceGraph's pydantic defaults (all Go zero).
func NewResourceGraph() ResourceGraph { return ResourceGraph{} }

// NewConfigDiff returns ConfigDiff's pydantic defaults (Any fields are nil,
// which marshals as null exactly as Python's None does).
func NewConfigDiff() ConfigDiff { return ConfigDiff{} }

// NewDriftedResource seeds iac_config={} / live_config={} / diffs=[] and
// significance="medium".
func NewDriftedResource() DriftedResource {
	return DriftedResource{
		IaCConfig:    map[string]any{},
		LiveConfig:   map[string]any{},
		Diffs:        []ConfigDiff{},
		Significance: "medium",
	}
}

// UnmarshalJSON seeds DriftedResource's dict/list defaults and significance.
func (d *DriftedResource) UnmarshalJSON(b []byte) error {
	*d = NewDriftedResource()
	type alias DriftedResource
	return decodeSeeded(b, (*alias)(d))
}

// NewDriftReport seeds all three list fields to empty slices.
func NewDriftReport() DriftReport {
	return DriftReport{
		DriftedResources:   []DriftedResource{},
		IaCOnlyResources:   []string{},
		CloudOnlyResources: []string{},
	}
}

// UnmarshalJSON seeds DriftReport's list defaults.
func (d *DriftReport) UnmarshalJSON(b []byte) error {
	*d = NewDriftReport()
	type alias DriftReport
	return decodeSeeded(b, (*alias)(d))
}

// NewReconResult seeds iac_type="terraform", providers_detected=[] and the two
// nested pointers-to-model defaults.
//
// Python parity caveat (doc.go): ReconResult's `default_factory=ResourceInventory`
// / `ResourceGraph` RAISE, because both inner models have a required field. Go
// cannot raise from a constructor, so the sub-models are seeded with their own
// constructors — producing the JSON the fixture pins, i.e. what
// `ReconResult(inventory=ResourceInventory(inventory_saved_path=""),
// resource_graph=ResourceGraph(graph_saved_path=""))` dumps.
func NewReconResult() ReconResult {
	return ReconResult{
		Inventory:         NewResourceInventory(),
		ResourceGraph:     NewResourceGraph(),
		IaCType:           "terraform",
		ProvidersDetected: []string{},
	}
}

// UnmarshalJSON seeds ReconResult's nested models, iac_type and list default.
func (r *ReconResult) UnmarshalJSON(b []byte) error {
	*r = NewReconResult()
	type alias ReconResult
	return decodeSeeded(b, (*alias)(r))
}

// --- hunt.go ----------------------------------------------------------------

// NewAffectedResource returns AffectedResource's pydantic defaults (all Go zero).
func NewAffectedResource() AffectedResource { return AffectedResource{} }

// NewRawFinding seeds resources=[], estimated_severity="medium",
// confidence="medium", and a fresh uuid4 for both id and fingerprint.
func NewRawFinding() RawFinding {
	return RawFinding{
		ID:                NewUUID4(),
		Resources:         []AffectedResource{},
		EstimatedSeverity: scoring.SeverityMedium,
		Confidence:        ConfidenceMedium,
		Fingerprint:       NewUUID4(),
	}
}

// UnmarshalJSON seeds RawFinding's defaults, including fresh uuid4s for id and
// fingerprint — pydantic calls the default_factory on every model_validate that
// omits the key, so two decodes of the same id-less payload yield distinct ids.
func (f *RawFinding) UnmarshalJSON(b []byte) error {
	*f = NewRawFinding()
	type alias RawFinding
	return decodeSeeded(b, (*alias)(f))
}

// NewHuntResult seeds findings=[] and strategies_run=[].
func NewHuntResult() HuntResult {
	return HuntResult{
		Findings:      []RawFinding{},
		StrategiesRun: []string{},
	}
}

// UnmarshalJSON seeds HuntResult's list defaults.
func (h *HuntResult) UnmarshalJSON(b []byte) error {
	*h = NewHuntResult()
	type alias HuntResult
	return decodeSeeded(b, (*alias)(h))
}

// --- chain.go ---------------------------------------------------------------

// NewAttackStep returns AttackStep's pydantic defaults (all Go zero).
func NewAttackStep() AttackStep { return AttackStep{} }

// NewBlastRadius seeds the three list fields to empty slices.
func NewBlastRadius() BlastRadius {
	return BlastRadius{
		DataStoresReachable: []string{},
		ComputeReachable:    []string{},
		ServicesAffected:    []string{},
	}
}

// UnmarshalJSON seeds BlastRadius's list defaults.
func (b2 *BlastRadius) UnmarshalJSON(b []byte) error {
	*b2 = NewBlastRadius()
	type alias BlastRadius
	return decodeSeeded(b, (*alias)(b2))
}

// NewAttackPath seeds a fresh uuid4 id, steps=[], findings_involved=[],
// combined_severity="high" and a defaulted BlastRadius.
func NewAttackPath() AttackPath {
	return AttackPath{
		ID:               NewUUID4(),
		Steps:            []AttackStep{},
		FindingsInvolved: []string{},
		CombinedSeverity: scoring.SeverityHigh,
		BlastRadius:      NewBlastRadius(),
	}
}

// UnmarshalJSON seeds AttackPath's defaults (including a fresh uuid4 id).
func (a *AttackPath) UnmarshalJSON(b []byte) error {
	*a = NewAttackPath()
	type alias AttackPath
	return decodeSeeded(b, (*alias)(a))
}

// NewChainResult seeds attack_paths=[].
func NewChainResult() ChainResult {
	return ChainResult{AttackPaths: []AttackPath{}}
}

// UnmarshalJSON seeds ChainResult's list default.
func (c *ChainResult) UnmarshalJSON(b []byte) error {
	*c = NewChainResult()
	type alias ChainResult
	return decodeSeeded(b, (*alias)(c))
}

// --- prove.go ---------------------------------------------------------------

// NewProof seeds method="static_analysis", evidence=[], scripts_executed=[] and
// verification_tier="static".
func NewProof() Proof {
	return Proof{
		Method:           ProofMethodStaticAnalysis,
		Evidence:         []string{},
		ScriptsExecuted:  []string{},
		VerificationTier: "static",
	}
}

// UnmarshalJSON seeds Proof's method, list defaults and verification_tier.
func (p *Proof) UnmarshalJSON(b []byte) error {
	*p = NewProof()
	type alias Proof
	return decodeSeeded(b, (*alias)(p))
}

// NewIaCDiff returns IaCDiff's pydantic defaults (all Go zero).
func NewIaCDiff() IaCDiff { return IaCDiff{} }

// NewRemediationSuggestion seeds diffs=[], effort="moderate" and
// alternative_approaches=[].
func NewRemediationSuggestion() RemediationSuggestion {
	return RemediationSuggestion{
		Diffs:                 []IaCDiff{},
		Effort:                "moderate",
		AlternativeApproaches: []string{},
	}
}

// UnmarshalJSON seeds RemediationSuggestion's list defaults and effort.
func (r *RemediationSuggestion) UnmarshalJSON(b []byte) error {
	*r = NewRemediationSuggestion()
	type alias RemediationSuggestion
	return decodeSeeded(b, (*alias)(r))
}

// NewVerifiedFinding seeds fresh uuid4s for id and fingerprint, resources=[],
// a defaulted Proof, and compliance_mappings=[].
//
// Python parity: verdict and severity are REQUIRED with no default, so they stay
// at the Go zero value ("") here — a caller must set them, exactly as pydantic
// forces. The fixture pins the dump of
// `VerifiedFinding(title="", verdict=CONFIRMED, severity=MEDIUM, category="")`,
// so parity_test.go supplies those two explicitly.
func NewVerifiedFinding() VerifiedFinding {
	return VerifiedFinding{
		ID:                 NewUUID4(),
		Resources:          []AffectedResource{},
		Proof:              NewProof(),
		ComplianceMappings: []string{},
		Fingerprint:        NewUUID4(),
	}
}

// UnmarshalJSON seeds VerifiedFinding's defaults (including fresh uuid4s).
func (v *VerifiedFinding) UnmarshalJSON(b []byte) error {
	*v = NewVerifiedFinding()
	type alias VerifiedFinding
	return decodeSeeded(b, (*alias)(v))
}

// --- input.go ---------------------------------------------------------------

// NewCloudConfig seeds provider="aws" and regions=["us-east-1"].
func NewCloudConfig() CloudConfig {
	return CloudConfig{
		Provider: "aws",
		Regions:  []string{"us-east-1"},
	}
}

// UnmarshalJSON seeds CloudConfig.provider="aws" and regions=["us-east-1"].
//
// Parity note: a payload that sets "regions": [] overrides the default with an
// empty list (pydantic does the same); only an ABSENT key keeps ["us-east-1"].
func (c *CloudConfig) UnmarshalJSON(b []byte) error {
	*c = NewCloudConfig()
	type alias CloudConfig
	return decodeSeeded(b, (*alias)(c))
}

// NewCloudSecurityInput seeds branch="main", depth="standard",
// severity_threshold="low", output_formats=["json"],
// compliance_frameworks=[] and exclude_paths=["tests/",".git/","examples/",".terraform/"].
//
// include_paths stays nil (Python's None).
func NewCloudSecurityInput() CloudSecurityInput {
	return CloudSecurityInput{
		Branch:               "main",
		Depth:                "standard",
		SeverityThreshold:    "low",
		OutputFormats:        []string{"json"},
		ComplianceFrameworks: []string{},
		ExcludePaths:         []string{"tests/", ".git/", "examples/", ".terraform/"},
	}
}

// UnmarshalJSON seeds CloudSecurityInput's scalar and list defaults.
func (in *CloudSecurityInput) UnmarshalJSON(b []byte) error {
	*in = NewCloudSecurityInput()
	type alias CloudSecurityInput
	return decodeSeeded(b, (*alias)(in))
}

// --- output.go --------------------------------------------------------------

// NewCloudSecurityScanResult seeds every default_factory=list field to an empty
// slice and every default_factory=dict field to an empty map.
//
// Timestamp is REQUIRED in Python with no default, so it stays the zero
// Timestamp here; orchestrator.py always passes datetime.now(UTC) (NowUTC()).
func NewCloudSecurityScanResult() CloudSecurityScanResult {
	return CloudSecurityScanResult{
		ProvidersDetected:           []string{},
		Findings:                    []VerifiedFinding{},
		AttackPaths:                 []AttackPath{},
		BySeverity:                  map[string]int{},
		ComplianceFrameworksChecked: []string{},
		ComplianceGaps:              []string{},
		StrategiesUsed:              []string{},
		CostBreakdown:               map[string]float64{},
		Metadata:                    map[string]any{},
	}
}

// UnmarshalJSON seeds CloudSecurityScanResult's list and dict defaults.
func (r *CloudSecurityScanResult) UnmarshalJSON(b []byte) error {
	*r = NewCloudSecurityScanResult()
	type alias CloudSecurityScanResult
	return decodeSeeded(b, (*alias)(r))
}

// NewScanProgress returns ScanProgress's defaults (every field is required in
// Python, so all Go zero).
func NewScanProgress() ScanProgress { return ScanProgress{} }

// NewScanMetrics seeds cost_breakdown={}.
func NewScanMetrics() ScanMetrics {
	return ScanMetrics{CostBreakdown: map[string]float64{}}
}

// UnmarshalJSON seeds ScanMetrics.cost_breakdown={}.
func (m *ScanMetrics) UnmarshalJSON(b []byte) error {
	*m = NewScanMetrics()
	type alias ScanMetrics
	return decodeSeeded(b, (*alias)(m))
}

// --- views.go ---------------------------------------------------------------

// NewFindingForDedup returns FindingForDedup's defaults (every field is required
// in Python, so all Go zero).
func NewFindingForDedup() FindingForDedup { return FindingForDedup{} }

// NewFindingForProver returns FindingForProver's defaults (all Go zero / nil).
func NewFindingForProver() FindingForProver { return FindingForProver{} }

// NewFindingForChain seeds resources=[].
func NewFindingForChain() FindingForChain {
	return FindingForChain{Resources: []string{}}
}

// UnmarshalJSON seeds FindingForChain.resources=[].
func (f *FindingForChain) UnmarshalJSON(b []byte) error {
	*f = NewFindingForChain()
	type alias FindingForChain
	return decodeSeeded(b, (*alias)(f))
}

// --- pathplan.go ------------------------------------------------------------

// NewChildInvestigation seeds findings_involved=[].
func NewChildInvestigation() ChildInvestigation {
	return ChildInvestigation{FindingsInvolved: []string{}}
}

// UnmarshalJSON seeds ChildInvestigation.findings_involved=[].
func (c *ChildInvestigation) UnmarshalJSON(b []byte) error {
	*c = NewChildInvestigation()
	type alias ChildInvestigation
	return decodeSeeded(b, (*alias)(c))
}

// NewPathInvestigationPlan seeds investigations=[].
func NewPathInvestigationPlan() PathInvestigationPlan {
	return PathInvestigationPlan{Investigations: []ChildInvestigation{}}
}

// UnmarshalJSON seeds PathInvestigationPlan.investigations=[].
func (p *PathInvestigationPlan) UnmarshalJSON(b []byte) error {
	*p = NewPathInvestigationPlan()
	type alias PathInvestigationPlan
	return decodeSeeded(b, (*alias)(p))
}
