package schemas

// This file ports src/cloudsecurity_af/schemas/input.py — the REST API input
// contract for cloudsecurity.scan and cloudsecurity.prove.

// CloudConfig ports input.py CloudConfig: cloud provider credentials and
// targeting configuration.
//
// Credentials are resolved from environment variables (AWS_ACCESS_KEY_ID, etc.),
// never passed in the API payload.
type CloudConfig struct {
	// Provider is one of aws | gcp | azure.
	Provider string `json:"provider"`
	// Regions are the cloud regions to scan.
	Regions []string `json:"regions"`
	// AccountID is the cloud account/project ID (optional, auto-detected if omitted).
	AccountID *string `json:"account_id"`
	// AssumeRoleARN is the AWS IAM role ARN to assume for scanning (OIDC-compatible).
	AssumeRoleARN *string `json:"assume_role_arn"`
}

// CloudSecurityInput ports input.py CloudSecurityInput: the top-level input for
// the cloudsecurity.scan and cloudsecurity.prove skills.
type CloudSecurityInput struct {
	// RepoURL is a git repository URL or local path containing IaC files.
	// Python parity: required (`Field(...)`).
	RepoURL string `json:"repo_url"`
	// Branch to scan.
	Branch string `json:"branch"`
	// CommitSHA is a specific commit SHA to scan.
	CommitSHA *string `json:"commit_sha"`
	// BaseCommitSHA is the base commit SHA for diff-aware PR scanning.
	BaseCommitSHA *string `json:"base_commit_sha"`
	// Depth is the scan depth profile: quick | standard | thorough.
	Depth string `json:"depth"`
	// SeverityThreshold is the minimum severity to report:
	// critical | high | medium | low | info.
	SeverityThreshold string   `json:"severity_threshold"`
	OutputFormats     []string `json:"output_formats"`
	// ComplianceFrameworks to check: cis_aws | soc2 | hipaa | pci_dss.
	ComplianceFrameworks []string `json:"compliance_frameworks"`

	// Cloud configuration (Tier 2+ — omit for static-only scans).
	Cloud *CloudConfig `json:"cloud"`

	// Budget controls.
	MaxCostUSD           *float64 `json:"max_cost_usd"`
	MaxDurationSeconds   *int     `json:"max_duration_seconds"`
	MaxConcurrentHunters *int     `json:"max_concurrent_hunters"`
	MaxConcurrentProvers *int     `json:"max_concurrent_provers"`

	// Path filtering.
	//
	// Python parity: include_paths is `list[str] | None = None`. A nil Go slice
	// already marshals as `null`, so no extra pointer indirection is needed —
	// nil means None, non-nil (including empty) means an explicit list.
	IncludePaths []string `json:"include_paths"`
	ExcludePaths []string `json:"exclude_paths"`

	// CI/CD integration.
	IsPR bool `json:"is_pr"`
	// PRID is the pull request identifier.
	PRID *string `json:"pr_id"`
	// FailOnFindings returns a non-zero exit status for CI gating.
	FailOnFindings bool `json:"fail_on_findings"`
}

// Tier ports the CloudSecurityInput.tier property: 1 when no cloud config is
// supplied (static-only), 2 otherwise.
//
// Python parity: it is a plain @property, NOT a pydantic field, so it does not
// appear in model_dump() and must not carry a json tag.
func (in CloudSecurityInput) Tier() int {
	if in.Cloud == nil {
		return 1
	}
	return 2
}
