package schemas

// This file ports src/cloudsecurity_af/schemas/recon.py — the RECON phase
// schemas (IaC reader output, resource-graph pointer, drift report, and the
// aggregated ReconResult).

// ---------------------------------------------------------------------------
// IaC Reader output
// ---------------------------------------------------------------------------

// Variable ports recon.py Variable: a Terraform variable or CloudFormation
// parameter.
type Variable struct {
	Name        string  `json:"name"`
	Type        *string `json:"type"`
	Default     *string `json:"default"`
	Description *string `json:"description"`
	FilePath    *string `json:"file_path"`
}

// Output ports recon.py Output: a Terraform or CloudFormation output.
type Output struct {
	Name        string  `json:"name"`
	Value       *string `json:"value"`
	Description *string `json:"description"`
	FilePath    *string `json:"file_path"`
}

// ProviderConfig ports recon.py ProviderConfig: a cloud provider block
// (e.g. aws, google, azurerm).
type ProviderConfig struct {
	Name    string  `json:"name"`
	Region  *string `json:"region"`
	Alias   *string `json:"alias"`
	Version *string `json:"version"`
}

// Module ports recon.py Module: a Terraform module reference.
type Module struct {
	Name     string  `json:"name"`
	Source   string  `json:"source"`
	Version  *string `json:"version"`
	FilePath *string `json:"file_path"`
}

// Resource ports recon.py Resource: an individual IaC resource (Terraform
// resource, CloudFormation resource, K8s object).
type Resource struct {
	// ID is e.g. "aws_s3_bucket.data_lake".
	ID string `json:"id"`
	// Type is e.g. "aws_s3_bucket".
	Type string `json:"type"`
	// Name is e.g. "data_lake".
	Name string `json:"name"`
	// Provider is one of aws | gcp | azure | kubernetes.
	Provider   string `json:"provider"`
	FilePath   string `json:"file_path"`
	LineNumber int    `json:"line_number"`
	// Config is the raw resource configuration.
	Config map[string]any `json:"config"`
	// References holds IDs of resources this depends on.
	References []string `json:"references"`
	// ReferencedBy holds IDs of resources that depend on this.
	ReferencedBy []string `json:"referenced_by"`
}

// ResourceInventory ports recon.py ResourceInventory: the inventory pointer the
// IaC reader harness returns.
//
// Python parity: InventorySavedPath is REQUIRED (no default), which is what
// makes ReconResult's default_factory unusable — see doc.go.
type ResourceInventory struct {
	// InventorySavedPath is the absolute path to the generated inventory.json.
	InventorySavedPath string `json:"inventory_saved_path"`
	TotalResources     int    `json:"total_resources"`
	// IaCType is one of terraform | cloudformation | kubernetes.
	IaCType    string  `json:"iac_type"`
	IaCVersion *string `json:"iac_version"`
}

// ---------------------------------------------------------------------------
// Resource Graph Builder output
// ---------------------------------------------------------------------------

// ResourceGraph ports recon.py ResourceGraph: the graph pointer the Resource
// Graph Builder harness returns.
//
// Python parity: GraphSavedPath is REQUIRED (no default).
type ResourceGraph struct {
	// GraphSavedPath is the absolute path to the generated graph.json.
	GraphSavedPath string `json:"graph_saved_path"`
	TotalNodes     int    `json:"total_nodes"`
	TotalEdges     int    `json:"total_edges"`
}

// ---------------------------------------------------------------------------
// Drift Detection output (Tier 2+)
// ---------------------------------------------------------------------------

// ConfigDiff ports recon.py ConfigDiff: a single attribute difference between
// IaC and live state. IaCValue/LiveValue are `Any = None` in Python.
type ConfigDiff struct {
	Attribute      string  `json:"attribute"`
	IaCValue       any     `json:"iac_value"`
	LiveValue      any     `json:"live_value"`
	SecurityImpact *string `json:"security_impact"`
}

// DriftedResource ports recon.py DriftedResource: a resource that has drifted
// from its IaC declaration.
type DriftedResource struct {
	ResourceID       string         `json:"resource_id"`
	ResourceType     string         `json:"resource_type"`
	IaCConfig        map[string]any `json:"iac_config"`
	LiveConfig       map[string]any `json:"live_config"`
	Diffs            []ConfigDiff   `json:"diffs"`
	SecurityRelevant bool           `json:"security_relevant"`
	// Significance is one of critical | high | medium | low.
	Significance string `json:"significance"`
}

// DriftReport ports recon.py DriftReport: the complete drift analysis between
// IaC and live cloud.
type DriftReport struct {
	DriftedResources []DriftedResource `json:"drifted_resources"`
	// IaCOnlyResources are declared in IaC but not deployed.
	IaCOnlyResources []string `json:"iac_only_resources"`
	// CloudOnlyResources are deployed but not in IaC (shadow IT).
	CloudOnlyResources []string `json:"cloud_only_resources"`
}

// ---------------------------------------------------------------------------
// Aggregated RECON result
// ---------------------------------------------------------------------------

// ReconResult ports recon.py ReconResult: the complete RECON phase output.
//
// Python parity: DriftReport and LiveInventory are only populated for Tier 2+
// scans. See doc.go for why Python's `ReconResult()` (no arguments) raises and
// how NewReconResult() reproduces the intended default vector instead.
type ReconResult struct {
	Inventory     ResourceInventory `json:"inventory"`
	ResourceGraph ResourceGraph     `json:"resource_graph"`
	// DriftReport is only populated for Tier 2+ scans.
	DriftReport *DriftReport `json:"drift_report"`
	// LiveInventory is the live cloud state (Tier 2+ only).
	LiveInventory        *ResourceInventory `json:"live_inventory"`
	IaCType              string             `json:"iac_type"`
	ProvidersDetected    []string           `json:"providers_detected"`
	TotalResources       int                `json:"total_resources"`
	TotalEdges           int                `json:"total_edges"`
	ReconDurationSeconds float64            `json:"recon_duration_seconds"`
}
