package phases

import (
	"context"
	"encoding/json"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
)

// This file transcribes the five phase reasoners' Python signatures — parameter
// names AND default values — into bindable input structs, so the reasoner
// adapters in internal/reasoners cannot drift from phases.py's contract and so
// the defaults are asserted by a test rather than repeated by hand.
//
// Each struct's UnmarshalJSON seeds the Python defaults before decoding, which
// is what pydantic/FastAPI does for a reasoner whose parameters have defaults:
// a key absent from the request body takes the signature's default, a key
// present with a null does NOT (it fails validation in Python; here it lands on
// the Go zero value, which is the same practical outcome for the two `| None`
// parameters and unreachable for the rest).
//
// Each struct also carries a Run method that is a thin, allocation-free
// forwarder to the positional phase function — the positional function stays
// the primary API.

// ReconPhaseInput is recon_phase's signature.
type ReconPhaseInput struct {
	RepoPath    string         `json:"repo_path"`
	Depth       string         `json:"depth"`
	Tier        int            `json:"tier"`
	CloudConfig map[string]any `json:"cloud_config"`
}

// NewReconPhaseInput returns recon_phase's default arguments.
func NewReconPhaseInput() ReconPhaseInput {
	return ReconPhaseInput{Depth: DefaultDepth, Tier: DefaultTier}
}

// UnmarshalJSON seeds recon_phase's defaults before decoding.
func (in *ReconPhaseInput) UnmarshalJSON(b []byte) error {
	*in = NewReconPhaseInput()
	type alias ReconPhaseInput
	return json.Unmarshal(b, (*alias)(in))
}

// Run invokes ReconPhase with these arguments.
func (in ReconPhaseInput) Run(ctx context.Context, app appx.Caller, nodeID string) (afx.Payload, error) {
	return ReconPhase(ctx, app, nodeID, in.RepoPath, in.Depth, in.Tier, in.CloudConfig)
}

// HuntPhaseInput is hunt_phase's signature.
type HuntPhaseInput struct {
	RepoPath             string `json:"repo_path"`
	ResourceGraphPath    string `json:"resource_graph_path"`
	InventoryPath        string `json:"inventory_path"`
	Depth                string `json:"depth"`
	MaxConcurrentHunters int    `json:"max_concurrent_hunters"`
}

// NewHuntPhaseInput returns hunt_phase's default arguments.
func NewHuntPhaseInput() HuntPhaseInput {
	return HuntPhaseInput{Depth: DefaultDepth, MaxConcurrentHunters: DefaultMaxConcurrentHunters}
}

// UnmarshalJSON seeds hunt_phase's defaults before decoding.
func (in *HuntPhaseInput) UnmarshalJSON(b []byte) error {
	*in = NewHuntPhaseInput()
	type alias HuntPhaseInput
	return json.Unmarshal(b, (*alias)(in))
}

// Run invokes HuntPhase with these arguments.
func (in HuntPhaseInput) Run(ctx context.Context, app appx.Caller, nodeID string) (afx.Payload, error) {
	return HuntPhase(ctx, app, nodeID, in.RepoPath, in.ResourceGraphPath, in.InventoryPath, in.Depth, in.MaxConcurrentHunters)
}

// ChainPhaseInput is chain_phase's signature.
//
// Findings is `[]any`, NOT `[]map[string]any`, and that is load-bearing.
// chain_phase is the ONE ported reasoner whose list parameter Python never
// binds: `findings: list[dict[str, Any]]` is forwarded straight into
// `run_path_constructor` (phases.py:225-243), and the SDK's
// `Agent._validate_handler_input` only checks `isinstance(value, list)` for a
// `list[...]` annotation — never the element type. Binding the elements to
// `map[string]any` here would fail the PARENT on `{"findings": [1, 2, "x"]}`,
// where Python fails the CHILD (RawFinding.model_validate(1) inside
// run_path_constructor) — a different DAG (no child node at all), a different
// error string and a 422 where Python answers with a relayed child failure.
// Compare ProvePhaseInput / RemediationPhaseInput, whose Python bodies DO
// model_validate, and whose Go fields are typed accordingly.
type ChainPhaseInput struct {
	Findings          []any          `json:"findings"`
	ResourceGraphPath string         `json:"resource_graph_path"`
	DriftReport       map[string]any `json:"drift_report"`
	Depth             string         `json:"depth"`
	MaxChildren       int            `json:"max_children"`
}

// NewChainPhaseInput returns chain_phase's default arguments.
func NewChainPhaseInput() ChainPhaseInput {
	return ChainPhaseInput{Depth: DefaultDepth, MaxChildren: DefaultMaxChildren}
}

// UnmarshalJSON seeds chain_phase's defaults before decoding.
func (in *ChainPhaseInput) UnmarshalJSON(b []byte) error {
	*in = NewChainPhaseInput()
	type alias ChainPhaseInput
	return json.Unmarshal(b, (*alias)(in))
}

// Run invokes ChainPhase with these arguments.
func (in ChainPhaseInput) Run(ctx context.Context, app appx.Caller, nodeID string) (afx.Payload, error) {
	return ChainPhase(ctx, app, nodeID, in.Findings, in.ResourceGraphPath, in.DriftReport, in.Depth, in.MaxChildren)
}

// ProvePhaseInput is prove_phase's signature.
type ProvePhaseInput struct {
	RepoPath             string         `json:"repo_path"`
	HuntResult           map[string]any `json:"hunt_result"`
	ChainResult          map[string]any `json:"chain_result"`
	Depth                string         `json:"depth"`
	Tier                 int            `json:"tier"`
	MaxConcurrentProvers int            `json:"max_concurrent_provers"`
}

// NewProvePhaseInput returns prove_phase's default arguments.
func NewProvePhaseInput() ProvePhaseInput {
	return ProvePhaseInput{Depth: DefaultDepth, Tier: DefaultTier, MaxConcurrentProvers: DefaultMaxConcurrentProvers}
}

// UnmarshalJSON seeds prove_phase's defaults before decoding.
func (in *ProvePhaseInput) UnmarshalJSON(b []byte) error {
	*in = NewProvePhaseInput()
	type alias ProvePhaseInput
	return json.Unmarshal(b, (*alias)(in))
}

// Run invokes ProvePhase with these arguments.
func (in ProvePhaseInput) Run(ctx context.Context, app appx.Caller, nodeID string) (afx.Payload, error) {
	return ProvePhase(ctx, app, nodeID, in.RepoPath, in.HuntResult, in.ChainResult, in.Depth, in.Tier, in.MaxConcurrentProvers)
}

// RemediationPhaseInput is remediation_phase's signature.
type RemediationPhaseInput struct {
	RepoPath                  string           `json:"repo_path"`
	VerifiedFindings          []map[string]any `json:"verified_findings"`
	MaxConcurrentRemediations int              `json:"max_concurrent_remediations"`
}

// NewRemediationPhaseInput returns remediation_phase's default arguments.
func NewRemediationPhaseInput() RemediationPhaseInput {
	return RemediationPhaseInput{MaxConcurrentRemediations: DefaultMaxConcurrentRemediations}
}

// UnmarshalJSON seeds remediation_phase's defaults before decoding.
func (in *RemediationPhaseInput) UnmarshalJSON(b []byte) error {
	*in = NewRemediationPhaseInput()
	type alias RemediationPhaseInput
	return json.Unmarshal(b, (*alias)(in))
}

// Run invokes RemediationPhase with these arguments.
func (in RemediationPhaseInput) Run(ctx context.Context, app appx.Caller, nodeID string) (afx.Payload, error) {
	return RemediationPhase(ctx, app, nodeID, in.RepoPath, in.VerifiedFindings, in.MaxConcurrentRemediations)
}

// --- Python signature transcriptions for the SDK input validation ------------
//
// HandlerInputFields feeds afx.ValidateHandlerInput, the port of the Python
// SDK's _validate_handler_input, which runs on the request body before the
// coroutine is entered. Required == the signature has NO default; Optional ==
// the annotation admits None. See internal/afx/handlerinput.go.

// HandlerInputFields is recon_phase's signature.
func (ReconPhaseInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
		{Name: "depth", Type: afx.TypeStr},
		{Name: "tier", Type: afx.TypeInt},
		{Name: "cloud_config", Type: afx.TypeDict, Optional: true},
	}
}

// HandlerInputFields is hunt_phase's signature.
func (HuntPhaseInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
		{Name: "resource_graph_path", Type: afx.TypeStr, Required: true},
		{Name: "inventory_path", Type: afx.TypeStr, Required: true},
		{Name: "depth", Type: afx.TypeStr},
		{Name: "max_concurrent_hunters", Type: afx.TypeInt},
	}
}

// HandlerInputFields is chain_phase's signature.
func (ChainPhaseInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "findings", Type: afx.TypeList, Required: true},
		{Name: "resource_graph_path", Type: afx.TypeStr, Required: true},
		{Name: "drift_report", Type: afx.TypeDict, Optional: true},
		{Name: "depth", Type: afx.TypeStr},
		{Name: "max_children", Type: afx.TypeInt},
	}
}

// HandlerInputFields is prove_phase's signature.
func (ProvePhaseInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
		{Name: "hunt_result", Type: afx.TypeDict, Required: true},
		{Name: "chain_result", Type: afx.TypeDict, Required: true},
		{Name: "depth", Type: afx.TypeStr},
		{Name: "tier", Type: afx.TypeInt},
		{Name: "max_concurrent_provers", Type: afx.TypeInt},
	}
}

// HandlerInputFields is remediation_phase's signature.
func (RemediationPhaseInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_path", Type: afx.TypeStr, Required: true},
		{Name: "verified_findings", Type: afx.TypeList, Required: true},
		{Name: "max_concurrent_remediations", Type: afx.TypeInt},
	}
}
