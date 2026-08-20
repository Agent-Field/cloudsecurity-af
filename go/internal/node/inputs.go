package node

// inputs.go transcribes the two @app.reasoner() signatures in
// src/cloudsecurity_af/app.py — `scan` and `prove` — into bindable input
// structs and the CloudSecurityInput construction each performs. The input
// schemas those two reasoners PUBLISH are not written here; they come from the
// Python-captured fixture (see the note at the bottom of this file and
// internal/reasoners/inputschema.go).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// The literal defaults shared by both signatures.
const (
	// DefaultDepth is `depth: str = "standard"`.
	DefaultDepth = "standard"
	// DefaultBranch is `branch: str = "main"`.
	DefaultBranch = "main"
	// DefaultSeverityThreshold is `severity_threshold: str = "low"`.
	DefaultSeverityThreshold = "low"
	// DefaultCloudProvider is prove()'s `cloud_provider: str = "aws"`.
	DefaultCloudProvider = "aws"
)

// defaultOutputFormats is the `output_formats or ["json"]` fallback.
func defaultOutputFormats() []string { return []string{"json"} }

// defaultExcludePaths is the
// `exclude_paths or ["tests/", ".git/", "examples/", ".terraform/"]` fallback.
//
// It is spelled out here rather than reused from config.DefaultExcludePaths()
// because app.py owns this list independently of the ScanConfig one; they
// happen to agree today and a test pins that.
func defaultExcludePaths() []string {
	return []string{"tests/", ".git/", "examples/", ".terraform/"}
}

// defaultCloudRegions is prove()'s `cloud_regions or ["us-east-1"]` fallback.
func defaultCloudRegions() []string { return []string{"us-east-1"} }

// ScanInput is app.py::scan's signature.
type ScanInput struct {
	RepoURL              string   `json:"repo_url"`
	Depth                string   `json:"depth"`
	Branch               string   `json:"branch"`
	CommitSHA            *string  `json:"commit_sha"`
	BaseCommitSHA        *string  `json:"base_commit_sha"`
	SeverityThreshold    string   `json:"severity_threshold"`
	OutputFormats        []string `json:"output_formats"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	MaxCostUSD           *float64 `json:"max_cost_usd"`
	MaxDurationSeconds   *int     `json:"max_duration_seconds"`
	MaxConcurrentHunters *int     `json:"max_concurrent_hunters"`
	MaxConcurrentProvers *int     `json:"max_concurrent_provers"`
	IncludePaths         []string `json:"include_paths"`
	ExcludePaths         []string `json:"exclude_paths"`
	IsPR                 bool     `json:"is_pr"`
	PRID                 *string  `json:"pr_id"`
	FailOnFindings       bool     `json:"fail_on_findings"`
}

// NewScanInput returns scan()'s default arguments.
func NewScanInput() ScanInput {
	return ScanInput{
		Depth:             DefaultDepth,
		Branch:            DefaultBranch,
		SeverityThreshold: DefaultSeverityThreshold,
	}
}

// UnmarshalJSON seeds scan()'s defaults before decoding, which is what FastAPI
// does for a parameter absent from the request body.
func (in *ScanInput) UnmarshalJSON(b []byte) error {
	*in = NewScanInput()
	type alias ScanInput
	return json.Unmarshal(b, (*alias)(in))
}

// CloudSecurityInput ports scan()'s CloudSecurityInput(...) construction.
//
// Python parity: `output_formats or ["json"]` and
// `exclude_paths or [...]` are TRUTHINESS fallbacks, so an explicitly EMPTY
// list also takes the default — only a non-empty list is honored. Likewise
// `compliance_frameworks or []` collapses None and [] to []. include_paths is
// passed through untouched, so None stays None.
//
// Python parity: cloud is None — `scan` is always a Tier 1 (static-only) run.
func (in ScanInput) CloudSecurityInput() schemas.CloudSecurityInput {
	out := schemas.NewCloudSecurityInput()
	out.RepoURL = in.RepoURL
	out.Depth = in.Depth
	out.Branch = in.Branch
	out.CommitSHA = in.CommitSHA
	out.BaseCommitSHA = in.BaseCommitSHA
	out.SeverityThreshold = in.SeverityThreshold
	out.OutputFormats = orDefault(in.OutputFormats, defaultOutputFormats())
	out.ComplianceFrameworks = orDefault(in.ComplianceFrameworks, []string{})
	out.Cloud = nil
	out.MaxCostUSD = in.MaxCostUSD
	out.MaxDurationSeconds = in.MaxDurationSeconds
	out.MaxConcurrentHunters = in.MaxConcurrentHunters
	out.MaxConcurrentProvers = in.MaxConcurrentProvers
	out.IncludePaths = in.IncludePaths
	out.ExcludePaths = orDefault(in.ExcludePaths, defaultExcludePaths())
	out.IsPR = in.IsPR
	out.PRID = in.PRID
	out.FailOnFindings = in.FailOnFindings
	return out
}

// HandlerInputFields transcribes scan()'s signature for
// afx.ValidateHandlerInput — the port of the Python SDK's
// _validate_handler_input, which runs on the request body BEFORE the coroutine
// is entered and answers 422 for a missing required parameter. `repo_url: str`
// has no default, so `cloudsecurity.scan {}` is a 422 in Python; without this
// the Go node bound repo_url to "" and resolveRepo("") fell through to the
// CLOUDSECURITY_REPO_PATH-or-cwd branch, scanning the node's own working
// directory and returning 200.
func (ScanInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_url", Type: afx.TypeStr, Required: true},
		{Name: "depth", Type: afx.TypeStr},
		{Name: "branch", Type: afx.TypeStr},
		{Name: "commit_sha", Type: afx.TypeStr, Optional: true},
		{Name: "base_commit_sha", Type: afx.TypeStr, Optional: true},
		{Name: "severity_threshold", Type: afx.TypeStr},
		{Name: "output_formats", Type: afx.TypeList, Optional: true},
		{Name: "compliance_frameworks", Type: afx.TypeList, Optional: true},
		{Name: "max_cost_usd", Type: afx.TypeFloat, Optional: true},
		{Name: "max_duration_seconds", Type: afx.TypeInt, Optional: true},
		{Name: "max_concurrent_hunters", Type: afx.TypeInt, Optional: true},
		{Name: "max_concurrent_provers", Type: afx.TypeInt, Optional: true},
		{Name: "include_paths", Type: afx.TypeList, Optional: true},
		{Name: "exclude_paths", Type: afx.TypeList, Optional: true},
		{Name: "is_pr", Type: afx.TypeBool},
		{Name: "pr_id", Type: afx.TypeStr, Optional: true},
		{Name: "fail_on_findings", Type: afx.TypeBool},
	}
}

// ProveInput is app.py::prove's signature.
//
// Python parity: prove() takes NEITHER base_commit_sha, max_concurrent_hunters,
// max_concurrent_provers NOR pr_id — those four keep CloudSecurityInput's own
// pydantic defaults (None). Adding them here would widen the API surface past
// Python's.
type ProveInput struct {
	RepoURL              string   `json:"repo_url"`
	CloudProvider        string   `json:"cloud_provider"`
	CloudRegions         []string `json:"cloud_regions"`
	AssumeRoleARN        *string  `json:"assume_role_arn"`
	Depth                string   `json:"depth"`
	Branch               string   `json:"branch"`
	CommitSHA            *string  `json:"commit_sha"`
	SeverityThreshold    string   `json:"severity_threshold"`
	OutputFormats        []string `json:"output_formats"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	MaxCostUSD           *float64 `json:"max_cost_usd"`
	MaxDurationSeconds   *int     `json:"max_duration_seconds"`
	IncludePaths         []string `json:"include_paths"`
	ExcludePaths         []string `json:"exclude_paths"`
	IsPR                 bool     `json:"is_pr"`
	FailOnFindings       bool     `json:"fail_on_findings"`
}

// NewProveInput returns prove()'s default arguments.
func NewProveInput() ProveInput {
	return ProveInput{
		CloudProvider:     DefaultCloudProvider,
		Depth:             DefaultDepth,
		Branch:            DefaultBranch,
		SeverityThreshold: DefaultSeverityThreshold,
	}
}

// UnmarshalJSON seeds prove()'s defaults before decoding.
func (in *ProveInput) UnmarshalJSON(b []byte) error {
	*in = NewProveInput()
	type alias ProveInput
	return json.Unmarshal(b, (*alias)(in))
}

// CloudSecurityInput ports prove()'s CloudSecurityInput(...) construction,
// including the CloudConfig that makes it a Tier 2 (live cloud) run.
func (in ProveInput) CloudSecurityInput() schemas.CloudSecurityInput {
	out := schemas.NewCloudSecurityInput()
	out.RepoURL = in.RepoURL
	out.Depth = in.Depth
	out.Branch = in.Branch
	out.CommitSHA = in.CommitSHA
	out.SeverityThreshold = in.SeverityThreshold
	out.OutputFormats = orDefault(in.OutputFormats, defaultOutputFormats())
	out.ComplianceFrameworks = orDefault(in.ComplianceFrameworks, []string{})
	out.Cloud = &schemas.CloudConfig{
		Provider: in.CloudProvider,
		Regions:  orDefault(in.CloudRegions, defaultCloudRegions()),
		// Python parity: CloudConfig(provider=…, regions=…, assume_role_arn=…)
		// leaves account_id at its None default.
		AccountID:     nil,
		AssumeRoleARN: in.AssumeRoleARN,
	}
	out.MaxCostUSD = in.MaxCostUSD
	out.MaxDurationSeconds = in.MaxDurationSeconds
	out.IncludePaths = in.IncludePaths
	out.ExcludePaths = orDefault(in.ExcludePaths, defaultExcludePaths())
	out.IsPR = in.IsPR
	out.FailOnFindings = in.FailOnFindings
	return out
}

// HandlerInputFields transcribes prove()'s signature. Python parity: prove()
// declares NEITHER base_commit_sha, max_concurrent_hunters,
// max_concurrent_provers NOR pr_id, and _validate_handler_input DROPS every
// undeclared body key, so sending one to `prove` has no effect in either node.
func (ProveInput) HandlerInputFields() []afx.Field {
	return []afx.Field{
		{Name: "repo_url", Type: afx.TypeStr, Required: true},
		{Name: "cloud_provider", Type: afx.TypeStr},
		{Name: "cloud_regions", Type: afx.TypeList, Optional: true},
		{Name: "assume_role_arn", Type: afx.TypeStr, Optional: true},
		{Name: "depth", Type: afx.TypeStr},
		{Name: "branch", Type: afx.TypeStr},
		{Name: "commit_sha", Type: afx.TypeStr, Optional: true},
		{Name: "severity_threshold", Type: afx.TypeStr},
		{Name: "output_formats", Type: afx.TypeList, Optional: true},
		{Name: "compliance_frameworks", Type: afx.TypeList, Optional: true},
		{Name: "max_cost_usd", Type: afx.TypeFloat, Optional: true},
		{Name: "max_duration_seconds", Type: afx.TypeInt, Optional: true},
		{Name: "include_paths", Type: afx.TypeList, Optional: true},
		{Name: "exclude_paths", Type: afx.TypeList, Optional: true},
		{Name: "is_pr", Type: afx.TypeBool},
		{Name: "fail_on_findings", Type: afx.TypeBool},
	}
}

// orDefault ports Python's `value or fallback` for a list: an EMPTY list is
// falsy, so both None and [] take the fallback.
func orDefault(value, fallback []string) []string {
	if len(value) == 0 {
		return fallback
	}
	return value
}

// scanHandler ports app.py::scan.
func (n *Node) scanHandler(ctx context.Context, input map[string]any) (any, error) {
	in, err := afx.BindHandlerInput[ScanInput](input)
	if err != nil {
		return nil, badInput(err)
	}
	return n.runPipeline(ctx, in.CloudSecurityInput())
}

// proveHandler ports app.py::prove.
func (n *Node) proveHandler(ctx context.Context, input map[string]any) (any, error) {
	in, err := afx.BindHandlerInput[ProveInput](input)
	if err != nil {
		return nil, badInput(err)
	}
	return n.runPipeline(ctx, in.CloudSecurityInput())
}

// badInput maps a request-body failure onto the status the Python endpoint
// answers with.
//
// A signature violation — a missing required parameter, an uncoercible scalar —
// is what _validate_handler_input raises, and the Python SDK renders it as
// HTTP 422 (agent.py:2120-2128). Anything else that trips the bind is a decode
// failure of an already-validated body, which Python cannot reach; it keeps the
// pre-existing 400.
func badInput(err error) error {
	var inputErr *afx.InputError
	if errors.As(err, &inputErr) {
		return inputErr.ExecuteError()
	}
	return &agent.ExecuteError{StatusCode: http.StatusBadRequest, Message: err.Error()}
}

// INPUT SCHEMAS for `scan` and `prove` are NOT declared here.
//
// They used to be hand transcriptions of the app.py signatures, richer than
// what Python actually publishes: typed `default`s, `additionalProperties:true`,
// and nullable parameters typed by their non-null base type
// (`"commit_sha":{"type":"string"}`). Every one of those three embellishments
// diverged from the live Python node, which derives the schema from the
// signature via Agent._types_to_json_schema and emits only
// {type, properties, required} — no defaults, no additionalProperties, and
// PEP-604 optionals collapsed to `{"type":"object"}`.
//
// The property NAME set and `required` agreed; 16 of scan's 17 property
// SCHEMAS and 15 of prove's 17 did not, so a caller reading the contract off
// discovery saw a different shape depending on which node answered. Both
// reasoners now publish reasoners.MustInputSchema(name) — the bytes captured
// from the live Python node. See internal/reasoners/inputschema.go for the
// fixture's provenance, its regeneration recipe and the mapping quirks.
//
// The richer typing survives where it does real work: ScanInput / ProveInput
// above still bind `commit_sha` to a *string and `output_formats` to a
// []string, so the port's DECODING is unchanged — only the published
// description of the contract moved into line with Python.
