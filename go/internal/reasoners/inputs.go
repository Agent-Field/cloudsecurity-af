package reasoners

import "github.com/Agent-Field/cloudsecurity-af/go/internal/afx"

// inputs.go transcribes the Python router-reasoner signatures — parameter names
// AND default values — into bindable input structs, one per distinct signature.
// FastAPI/agentfield derive each reasoner's request contract from the signature,
// so these structs ARE the wire contract; keeping them here (rather than
// unpacking a map inside every handler) means the parity test can assert the
// key sets and defaults directly.
//
// None of these signatures has a non-zero scalar default, so none of them needs
// the default-seeding UnmarshalJSON that internal/phases' input structs carry.
// The only defaulted parameters are the two `| None = None` ones
// (`drift_report`, `attack_path`), whose Python default is None == a nil Go map.

// IaCReaderInput is run_iac_reader's signature (reasoners/recon.py):
//
//	async def run_iac_reader(repo_path: str) -> dict[str, Any]
type IaCReaderInput struct {
	RepoPath string `json:"repo_path"`
}

// ResourceGraphBuilderInput is run_resource_graph_builder's signature:
//
//	async def run_resource_graph_builder(repo_path: str, inventory_path: str)
type ResourceGraphBuilderInput struct {
	RepoPath      string `json:"repo_path"`
	InventoryPath string `json:"inventory_path"`
}

// CloudConnectorInput is run_cloud_connector's signature:
//
//	async def run_cloud_connector(cloud_config: dict[str, Any])
type CloudConnectorInput struct {
	CloudConfig map[string]any `json:"cloud_config"`
}

// DriftDetectorInput is run_drift_detector's signature:
//
//	async def run_drift_detector(iac_graph_path: str, cloud_config: dict[str, Any])
type DriftDetectorInput struct {
	IaCGraphPath string         `json:"iac_graph_path"`
	CloudConfig  map[string]any `json:"cloud_config"`
}

// HunterInput is the signature all SEVEN hunters share (reasoners/hunt.py):
//
//	async def run_<domain>_hunter(repo_path: str, resource_graph_path: str,
//	                              inventory_path: str, depth: str)
//
// Python parity: `depth` carries NO default here (unlike the phase reasoners),
// so an omitted depth binds to "" and is passed through to the hunter verbatim.
type HunterInput struct {
	RepoPath          string `json:"repo_path"`
	ResourceGraphPath string `json:"resource_graph_path"`
	InventoryPath     string `json:"inventory_path"`
	Depth             string `json:"depth"`
}

// PathConstructorInput is run_path_constructor's signature (reasoners/chain.py):
//
//	async def run_path_constructor(findings: list[dict[str, Any]],
//	                               resource_graph_path: str, max_paths: int,
//	                               max_children: int,
//	                               drift_report: dict[str, Any] | None = None)
type PathConstructorInput struct {
	Findings          []map[string]any `json:"findings"`
	ResourceGraphPath string           `json:"resource_graph_path"`
	MaxPaths          int              `json:"max_paths"`
	MaxChildren       int              `json:"max_children"`
	DriftReport       map[string]any   `json:"drift_report"`
}

// ProverInput is the signature run_static_prover and run_live_prover share
// (reasoners/prove.py):
//
//	async def run_<x>_prover(repo_path: str, finding: dict[str, Any], tier: int,
//	                         attack_path: dict[str, Any] | None = None)
type ProverInput struct {
	RepoPath   string         `json:"repo_path"`
	Finding    map[string]any `json:"finding"`
	Tier       int            `json:"tier"`
	AttackPath map[string]any `json:"attack_path"`
}

// FixGeneratorInput is run_fix_generator's signature (reasoners/remediate.py):
//
//	async def run_fix_generator(repo_path: str, finding: dict[str, Any])
type FixGeneratorInput struct {
	RepoPath string         `json:"repo_path"`
	Finding  map[string]any `json:"finding"`
}

// --- Python signature transcriptions for the SDK input validation ------------
//
// HandlerInputFields is the (name, annotation, has-default) triple of each
// parameter, which the Python SDK's _validate_handler_input consumes before the
// coroutine is entered. See internal/afx/handlerinput.go for the full contract.
//
// Required == the Python signature has NO default; Optional == the annotation
// admits None. Only `drift_report` and `attack_path` are `| None = None` here;
// every other parameter of every router reasoner is required and non-nullable.

// HandlerInputFields is `run_iac_reader(repo_path: str)`.
func (IaCReaderInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
	}
}

// HandlerInputFields is `run_resource_graph_builder(repo_path: str, inventory_path: str)`.
func (ResourceGraphBuilderInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
		{Name: "inventory_path", Type: afx.TypeStr, Required: true},
	}
}

// HandlerInputFields is `run_cloud_connector(cloud_config: dict[str, Any])`.
func (CloudConnectorInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "cloud_config", Type: afx.TypeDict, Required: true},
	}
}

// HandlerInputFields is `run_drift_detector(iac_graph_path: str, cloud_config: dict[str, Any])`.
func (DriftDetectorInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "iac_graph_path", Type: afx.TypeStr, Required: true},
		{Name: "cloud_config", Type: afx.TypeDict, Required: true},
	}
}

// HandlerInputFields is the signature all seven hunters share. NOTE `depth`
// carries no default here, unlike on the phase reasoners.
func (HunterInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
		{Name: "resource_graph_path", Type: afx.TypeStr, Required: true},
		{Name: "inventory_path", Type: afx.TypeStr, Required: true},
		{Name: "depth", Type: afx.TypeStr, Required: true},
	}
}

// HandlerInputFields is run_path_constructor's signature.
func (PathConstructorInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "findings", Type: afx.TypeList, Required: true},
		{Name: "resource_graph_path", Type: afx.TypeStr, Required: true},
		{Name: "max_paths", Type: afx.TypeInt, Required: true},
		{Name: "max_children", Type: afx.TypeInt, Required: true},
		{Name: "drift_report", Type: afx.TypeDict, Optional: true},
	}
}

// HandlerInputFields is the signature run_static_prover and run_live_prover share.
func (ProverInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
		{Name: "finding", Type: afx.TypeDict, Required: true},
		{Name: "tier", Type: afx.TypeInt, Required: true},
		{Name: "attack_path", Type: afx.TypeDict, Optional: true},
	}
}

// HandlerInputFields is `run_fix_generator(repo_path: str, finding: dict[str, Any])`.
func (FixGeneratorInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
		{Name: "finding", Type: afx.TypeDict, Required: true},
	}
}
