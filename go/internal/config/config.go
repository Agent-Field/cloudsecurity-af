// Package config ports src/cloudsecurity_af/config.py in full: the depth
// profile enum and its three lookup tables, BudgetConfig, ScanConfig (+
// from_input) and AIIntegrationConfig (+ from_env / provider_env).
//
// Every environment variable is read at CALL time — inside FromEnv /
// ProviderEnv — never at package init, so a t.Setenv in a test is deterministic
// and no value is frozen at import. (Python freezes them at model construction
// instead, which for app.py happens at import; the practical difference only
// shows up in tests, where Python uses monkeypatch + a fresh from_env() call.)
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DepthProfile ports config.py DepthProfile — a str-valued enum, so the wire
// representation is the bare lowercase word and a Go string type is exact.
type DepthProfile string

// The three profiles. Values are the Python enum values verbatim.
const (
	DepthQuick    DepthProfile = "quick"
	DepthStandard DepthProfile = "standard"
	DepthThorough DepthProfile = "thorough"
)

// ParseDepth ports `DepthProfile(value)` — the STRICT constructor used by
// ScanConfig.from_input. It is case-sensitive and rejects anything that is not
// one of the three values, with Python's own ValueError text:
//
//	>>> DepthProfile("bogus")
//	ValueError: 'bogus' is not a valid DepthProfile
//	>>> DepthProfile("Quick")
//	ValueError: 'Quick' is not a valid DepthProfile
//
// Use NormalizeDepth (not this) wherever the Python source called
// _normalize_depth.
func ParseDepth(value string) (DepthProfile, error) {
	switch DepthProfile(value) {
	case DepthQuick, DepthStandard, DepthThorough:
		return DepthProfile(value), nil
	}
	return "", fmt.Errorf("'%s' is not a valid DepthProfile", value)
}

// NormalizeDepth ports the _normalize_depth helper in
// src/cloudsecurity_af/reasoners/phases.py, which every phase reasoner uses on
// its `depth` string parameter:
//
//	def _normalize_depth(depth: str) -> DepthProfile:
//	    try:
//	        return DepthProfile(depth.lower())
//	    except ValueError:
//	        return DepthProfile.STANDARD
//
// Python parity: it lowercases first (so "QUICK" resolves) and silently falls
// back to STANDARD for anything unrecognized — including the empty string.
func NormalizeDepth(depth string) DepthProfile {
	p, err := ParseDepth(strings.ToLower(depth))
	if err != nil {
		return DepthStandard
	}
	return p
}

// BudgetConfig ports config.py BudgetConfig. The pointer fields are Python's
// `float | None` / `int | None`: nil means "no cap", which is NOT the same as 0.
type BudgetConfig struct {
	MaxCostUSD                 *float64 `json:"max_cost_usd"`
	MaxDurationSeconds         *int     `json:"max_duration_seconds"`
	MaxConcurrentHunters       int      `json:"max_concurrent_hunters"`
	MaxConcurrentProvers       int      `json:"max_concurrent_provers"`
	MaxConcurrentChainChildren int      `json:"max_concurrent_chain_children"`
	ReconBudgetPct             float64  `json:"recon_budget_pct"`
	HuntBudgetPct              float64  `json:"hunt_budget_pct"`
	ChainBudgetPct             float64  `json:"chain_budget_pct"`
	ProveBudgetPct             float64  `json:"prove_budget_pct"`
	RemediateBudgetPct         float64  `json:"remediate_budget_pct"`
}

// NewBudgetConfig ports `BudgetConfig()` — the pydantic field defaults. Go zero
// values differ from every one of them, so nothing may construct a
// BudgetConfig literal without going through here (or UnmarshalJSON).
func NewBudgetConfig() BudgetConfig {
	return BudgetConfig{
		MaxCostUSD:                 nil,
		MaxDurationSeconds:         nil,
		MaxConcurrentHunters:       4,
		MaxConcurrentProvers:       3,
		MaxConcurrentChainChildren: 3,
		ReconBudgetPct:             0.10,
		HuntBudgetPct:              0.35,
		ChainBudgetPct:             0.20,
		ProveBudgetPct:             0.25,
		RemediateBudgetPct:         0.10,
	}
}

// UnmarshalJSON seeds the pydantic defaults before decoding, so a BudgetConfig
// that crosses a reasoner boundary as a partial object comes back with the same
// values Python's model_validate would produce.
func (b *BudgetConfig) UnmarshalJSON(data []byte) error {
	type alias BudgetConfig
	seeded := alias(NewBudgetConfig())
	if err := json.Unmarshal(data, &seeded); err != nil {
		return err
	}
	*b = BudgetConfig(seeded)
	return nil
}

// DepthHunterMap ports config.py DEPTH_HUNTER_MAP: which hunt strategies each
// depth profile runs, IN ORDER (hunt_phase preserves this order when it fans
// out, so it is part of the DAG contract, not just a set).
var DepthHunterMap = map[DepthProfile][]string{
	DepthQuick:    {"iam", "network", "data", "secrets", "compute"},
	DepthStandard: {"iam", "network", "data", "secrets", "compute", "logging", "compliance"},
	DepthThorough: {"iam", "network", "data", "secrets", "compute", "logging", "compliance"},
}

// DepthChainLimits ports config.py DEPTH_CHAIN_LIMITS — max_paths handed to
// run_path_constructor.
var DepthChainLimits = map[DepthProfile]int{
	DepthQuick:    5,
	DepthStandard: 15,
	DepthThorough: 100,
}

// DepthProverCaps ports config.py DEPTH_PROVER_CAPS — how many findings
// prove_phase will hand to a prover.
//
// NOTE for reviewers: tests/test_config.py on main asserts
// DEPTH_PROVER_CAPS[QUICK] == 10, but config.py says 20 — that Python test is
// STALE and fails on main today (verified with this repo's interpreter). The
// Go port follows the CODE, which is what actually runs; see
// TestDepthProverCaps_QuickIsTwentyNotTheStalePythonTestValue.
var DepthProverCaps = map[DepthProfile]int{
	DepthQuick:    20,
	DepthStandard: 30,
	DepthThorough: 10_000,
}

// HuntersForDepth returns a COPY of the hunter list for a profile, so callers
// cannot mutate the shared table. An unknown profile yields the standard list,
// matching how every caller reaches this map through NormalizeDepth.
func HuntersForDepth(profile DepthProfile) []string {
	src, ok := DepthHunterMap[profile]
	if !ok {
		src = DepthHunterMap[DepthStandard]
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// DefaultExcludePaths ports the exclude_paths default_factory shared by
// ScanConfig and schemas.CloudSecurityInput. Returns a fresh slice each call
// (a default_factory produces a new list per model instance).
func DefaultExcludePaths() []string {
	return []string{"tests/", ".git/", "examples/", ".terraform/"}
}

// DefaultOutputFormats ports the output_formats default_factory (["json"]).
func DefaultOutputFormats() []string {
	return []string{"json"}
}

// ScanConfig ports config.py ScanConfig — the resolved per-run configuration
// the orchestrator and every phase read.
type ScanConfig struct {
	RepoPath             string       `json:"repo_path"`
	Depth                DepthProfile `json:"depth"`
	Tier                 int          `json:"tier"`
	SeverityThreshold    string       `json:"severity_threshold"`
	OutputFormats        []string     `json:"output_formats"`
	ComplianceFrameworks []string     `json:"compliance_frameworks"`
	IncludePaths         []string     `json:"include_paths"`
	ExcludePaths         []string     `json:"exclude_paths"`
	Budget               BudgetConfig `json:"budget"`
}

// NewScanConfig ports `ScanConfig(repo_path=...)` — the pydantic field defaults
// with only repo_path supplied.
func NewScanConfig(repoPath string) ScanConfig {
	return ScanConfig{
		RepoPath:             repoPath,
		Depth:                DepthStandard,
		Tier:                 1,
		SeverityThreshold:    "low",
		OutputFormats:        DefaultOutputFormats(),
		ComplianceFrameworks: []string{},
		IncludePaths:         nil,
		ExcludePaths:         DefaultExcludePaths(),
		Budget:               NewBudgetConfig(),
	}
}

// UnmarshalJSON seeds the pydantic defaults before decoding.
func (s *ScanConfig) UnmarshalJSON(data []byte) error {
	type alias ScanConfig
	seeded := alias(NewScanConfig(""))
	if err := json.Unmarshal(data, &seeded); err != nil {
		return err
	}
	*s = ScanConfig(seeded)
	return nil
}

// ScanInput is the read-only view of schemas.CloudSecurityInput that
// ScanConfig.from_input reads. It exists so this package does not have to
// import internal/schemas (Python's config.py DOES import schemas.input; the Go
// port keeps the dependency out so config stays a leaf package that the schemas
// owner can also import if it ever needs the depth tables).
//
// The json tags are the pydantic field names, so ScanConfigFromInput can decode
// a marshaled schemas.CloudSecurityInput — or the raw reasoner-boundary map —
// straight into this view.
type ScanInput struct {
	Depth                string   `json:"depth"`
	SeverityThreshold    string   `json:"severity_threshold"`
	OutputFormats        []string `json:"output_formats"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	IncludePaths         []string `json:"include_paths"`
	ExcludePaths         []string `json:"exclude_paths"`
	MaxCostUSD           *float64 `json:"max_cost_usd"`
	MaxDurationSeconds   *int     `json:"max_duration_seconds"`
	MaxConcurrentHunters *int     `json:"max_concurrent_hunters"`
	MaxConcurrentProvers *int     `json:"max_concurrent_provers"`

	// Tier ports CloudSecurityInput.tier, a @property (1 when `cloud` is None,
	// else 2). It is NOT a serialized field, so ScanConfigFromInput derives it
	// from the presence of a non-null `cloud` key rather than reading it.
	Tier int `json:"-"`
}

// ScanConfigFromInput ports ScanConfig.from_input.
//
// Python:
//
//	@classmethod
//	def from_input(cls, scan_input: CloudSecurityInput, repo_path: str) -> ScanConfig:
//	    depth = DepthProfile(scan_input.depth)
//	    budget = BudgetConfig(max_cost_usd=..., max_duration_seconds=...)
//	    if scan_input.max_concurrent_hunters is not None: budget.max_concurrent_hunters = ...
//	    if scan_input.max_concurrent_provers is not None: budget.max_concurrent_provers = ...
//	    return cls(repo_path=repo_path, depth=depth, tier=scan_input.tier, ...)
//
// Python parity: the depth is parsed with the STRICT DepthProfile constructor,
// so an unrecognized depth is a ValueError — which app.py maps to HTTP 400.
// It is deliberately NOT normalized here (only the phase reasoners normalize).
//
// scanInput may be any value whose JSON encoding matches
// schemas.CloudSecurityInput: the struct itself (the normal call, matching
// Python's typed argument) or the raw input map. Pass the MATERIALIZED struct
// where possible — a raw map that omits keys has no pydantic defaults behind
// it, exactly as in Python.
func ScanConfigFromInput(scanInput any, repoPath string) (ScanConfig, error) {
	view, err := scanInputView(scanInput)
	if err != nil {
		return ScanConfig{}, err
	}
	return NewScanConfigFromView(view, repoPath)
}

// NewScanConfigFromView is ScanConfigFromInput's pure core, for callers that
// already hold the field values.
func NewScanConfigFromView(in ScanInput, repoPath string) (ScanConfig, error) {
	depth, err := ParseDepth(in.Depth)
	if err != nil {
		return ScanConfig{}, err
	}

	budget := NewBudgetConfig()
	budget.MaxCostUSD = in.MaxCostUSD
	budget.MaxDurationSeconds = in.MaxDurationSeconds
	if in.MaxConcurrentHunters != nil {
		budget.MaxConcurrentHunters = *in.MaxConcurrentHunters
	}
	if in.MaxConcurrentProvers != nil {
		budget.MaxConcurrentProvers = *in.MaxConcurrentProvers
	}

	cfg := NewScanConfig(repoPath)
	cfg.Depth = depth
	cfg.Tier = in.Tier
	cfg.SeverityThreshold = in.SeverityThreshold
	cfg.OutputFormats = in.OutputFormats
	cfg.ComplianceFrameworks = in.ComplianceFrameworks
	cfg.IncludePaths = in.IncludePaths
	cfg.ExcludePaths = in.ExcludePaths
	cfg.Budget = budget
	return cfg, nil
}

// scanInputView JSON-round-trips an arbitrary input value into the ScanInput
// view and derives Tier from the `cloud` key the way CloudSecurityInput.tier
// does (`1 if self.cloud is None else 2`).
func scanInputView(scanInput any) (ScanInput, error) {
	if v, ok := scanInput.(ScanInput); ok {
		return v, nil
	}
	b, err := json.Marshal(scanInput)
	if err != nil {
		return ScanInput{}, fmt.Errorf("config: marshal scan input %T: %w", scanInput, err)
	}
	var view ScanInput
	if err := json.Unmarshal(b, &view); err != nil {
		return ScanInput{}, fmt.Errorf("config: decode scan input %T: %w", scanInput, err)
	}
	var probe struct {
		Cloud json.RawMessage `json:"cloud"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return ScanInput{}, fmt.Errorf("config: decode scan input %T: %w", scanInput, err)
	}
	view.Tier = 1
	if len(probe.Cloud) > 0 && string(probe.Cloud) != "null" {
		view.Tier = 2
	}
	return view, nil
}

// AIIntegrationConfig ports config.py AIIntegrationConfig.
type AIIntegrationConfig struct {
	Provider     string `json:"provider"`
	HarnessModel string `json:"harness_model"`
	AIModel      string `json:"ai_model"`
	MaxTurns     int    `json:"max_turns"`
	OpencodeBin  string `json:"opencode_bin"`
	AforgeBin    string `json:"aforge_bin"`
}

// AIConfigFromEnv ports AIIntegrationConfig.from_env() — i.e. constructing the
// model so every default_factory lambda runs. The precedence chains are the
// nested os.getenv calls, verbatim:
//
//	provider      CLOUDSECURITY_PROVIDER    -> HARNESS_PROVIDER -> "aforge"
//	harness_model CLOUDSECURITY_MODEL       -> HARNESS_MODEL    -> "openrouter/minimax/minimax-m2.5"
//	ai_model      CLOUDSECURITY_AI_MODEL    -> AI_MODEL -> CLOUDSECURITY_MODEL -> "openrouter/minimax/minimax-m2.5"
//	max_turns     int(CLOUDSECURITY_MAX_TURNS or "50")
//	opencode_bin  CLOUDSECURITY_OPENCODE_BIN -> "opencode"
//	aforge_bin    CLOUDSECURITY_AFORGE_BIN   -> AFORGE_BIN -> "aforge"
//
// Python parity: os.getenv(key, default) substitutes the default only when the
// key is ABSENT — a key set to the empty string yields "". strEnv keeps that.
//
// Python parity: a malformed CLOUDSECURITY_MAX_TURNS makes int() raise inside
// the default_factory, which happens while app.py is being imported — i.e. the
// node fails to boot. Go returns the error so the caller (node.BuildAgent) can
// fail startup the same way.
func AIConfigFromEnv() (AIIntegrationConfig, error) {
	maxTurns, err := intEnv("CLOUDSECURITY_MAX_TURNS", 50)
	if err != nil {
		return AIIntegrationConfig{}, err
	}
	return AIIntegrationConfig{
		Provider:     strEnv("CLOUDSECURITY_PROVIDER", strEnv("HARNESS_PROVIDER", "aforge")),
		HarnessModel: strEnv("CLOUDSECURITY_MODEL", strEnv("HARNESS_MODEL", defaultModel)),
		AIModel: strEnv("CLOUDSECURITY_AI_MODEL",
			strEnv("AI_MODEL", strEnv("CLOUDSECURITY_MODEL", defaultModel))),
		MaxTurns:    maxTurns,
		OpencodeBin: strEnv("CLOUDSECURITY_OPENCODE_BIN", "opencode"),
		AforgeBin:   strEnv("CLOUDSECURITY_AFORGE_BIN", strEnv("AFORGE_BIN", "aforge")),
	}, nil
}

// defaultModel is the code default for both harness_model and ai_model.
const defaultModel = "openrouter/minimax/minimax-m2.5"

// providerEnvKeys ports the env_keys tuple in provider_env(), IN ORDER. Only
// keys with a non-empty value are forwarded (Python's walrus `if (value :=
// os.getenv(key))` is a truthiness test, so a key set to "" is dropped).
var providerEnvKeys = []string{
	"OPENROUTER_API_KEY",
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"GOOGLE_API_KEY",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_REGION",
	"AWS_DEFAULT_REGION",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"AZURE_CLIENT_ID",
	"AZURE_CLIENT_SECRET",
	"AZURE_TENANT_ID",
	"AZURE_SUBSCRIPTION_ID",
}

// ProviderEnvKeys returns a copy of the forwarded-credential key list, for
// tests and for the packaging manifest to cross-check against.
func ProviderEnvKeys() []string {
	out := make([]string, len(providerEnvKeys))
	copy(out, providerEnvKeys)
	return out
}

// ProviderEnv ports AIIntegrationConfig.provider_env(): the environment handed
// to the harness subprocess.
//
//   - the 14 cloud/LLM credential keys, forwarded only when non-empty
//   - AGENTFIELD_AFORGE_COMMAND, defaulting to "exec"
//   - XDG_DATA_HOME, defaulting to <tempdir>/opencode-shared-data, and CREATED
//     (Python: os.makedirs(xdg, exist_ok=True)) because opencode refuses to run
//     without a writable data home
//
// Python parity: XDG_DATA_HOME uses `or`, not os.getenv's default, so a key set
// to "" ALSO falls back to the temp path — unlike AGENTFIELD_AFORGE_COMMAND,
// which uses os.getenv(key, "exec") and therefore keeps an explicit "".
//
// Divergence (documented, benign): Python's tempfile.gettempdir() consults
// TMPDIR/TEMP/TMP then falls back through /tmp, while Go's os.TempDir() reads
// $TMPDIR and falls back to /tmp. They agree on every Linux container this node
// runs in.
//
// Python parity — THE MKDIR FAILURE IS FATAL AT BOOT. config.py:135 is a bare
// `os.makedirs(xdg, exist_ok=True)` (exist_ok suppresses only FileExistsError),
// and provider_env() is called from app.py's MODULE BODY, inside the
// `Agent(... harness_config=HarnessConfig(env=_ai_config.provider_env(), ...))`
// literal. So an unwritable XDG_DATA_HOME — a read-only volume, a path
// component that is a regular file, a uid without write access to $TMPDIR —
// raises at import and the process never registers with the control plane.
// Verified against the repo venv: with XDG_DATA_HOME under a regular file,
// AIIntegrationConfig.from_env().provider_env() raises NotADirectoryError.
// Returning the error (rather than swallowing it) keeps the Go node failing
// where the Python node fails, instead of registering healthy and then failing
// every scan deep inside the first harness invocation.
func (c AIIntegrationConfig) ProviderEnv() (map[string]string, error) {
	env := make(map[string]string, len(providerEnvKeys)+2)
	for _, key := range providerEnvKeys {
		if v := os.Getenv(key); v != "" {
			env[key] = v
		}
	}
	env["AGENTFIELD_AFORGE_COMMAND"] = strEnv("AGENTFIELD_AFORGE_COMMAND", "exec")

	xdg := os.Getenv("XDG_DATA_HOME")
	if xdg == "" {
		xdg = filepath.Join(os.TempDir(), "opencode-shared-data")
	}
	if err := os.MkdirAll(xdg, 0o755); err != nil {
		return nil, fmt.Errorf("config.ProviderEnv: create XDG_DATA_HOME %q: %w", xdg, err)
	}
	env["XDG_DATA_HOME"] = xdg
	return env, nil
}

// --- node identity ---------------------------------------------------------

// DefaultNodeID is the fallback in every `os.getenv("NODE_ID", "cloudsecurity")`
// the Python node performs: app.py:31, reasoners/phases.py:22 and
// orchestrator.py:73.
const DefaultNodeID = "cloudsecurity"

// NodeID resolves the node's identity from NODE_ID.
//
// This is THE single resolution rule for the whole port. Python reads the same
// `os.getenv("NODE_ID", "cloudsecurity")` in all three places, so the id the
// node REGISTERS under and the prefix of every `app.call` DAG target can never
// disagree. Go must preserve that invariant: internal/node uses it for
// agent.Config.NodeID, internal/phases and internal/orch use it for every Call
// target. Resolving NODE_ID with two different rules would let the node
// register as `cloudsecurity` while calling `".recon_phase"`, which the SDK
// does not repair (Agent.Call only prefixes targets that contain no dot) and
// which fails only at the first phase call, long after a clean boot.
//
// DIVERGENCE (deliberate, and the reason this helper exists): an EMPTY NODE_ID
// is treated as absent, where Python's os.getenv would return "". `af run` and
// docker compose export empty strings for unset optional variables, and an
// empty node id cannot produce a working node in either language. The
// divergence is safe precisely because it is applied uniformly — registration
// and call targets both fall back to the same default.
func NodeID() string { return NodeIDOr(DefaultNodeID) }

// NodeIDOr is NodeID with a caller-supplied default, for cmd/ mains that pass
// their own (identical) default down into node.BuildAgent.
func NodeIDOr(def string) string {
	if v := os.Getenv("NODE_ID"); v != "" {
		return v
	}
	return def
}

// --- shared env readers (call-time only) ---

// strEnv returns the env value for key, or def when the key is UNSET. A key
// that is set (even to "") returns its value, matching os.getenv(key, def).
func strEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// intEnv parses key as an int, falling back to def when the key is unset. A
// set-but-malformed value is an error carrying Python's int() message shape;
// Python's int(os.getenv(...)) raises, it never silently defaults.
func intEnv(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("invalid literal for int() with base 10: '%s'", v)
	}
	return n, nil
}
