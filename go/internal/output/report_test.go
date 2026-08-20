package output

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// Behaviour tests for output/report.py, derived from the Python source's
// observable behaviour. The byte-level agreement is golden_test.go's job; this
// file pins the truthiness guards and the numeric formats one at a time.

// reportOf renders a result and splits it into lines for assertion.
func reportOf(result schemas.CloudSecurityScanResult) []string {
	return strings.Split(GenerateReport(result), "\n")
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

func lineWithPrefix(t *testing.T, lines []string, prefix string) string {
	t.Helper()
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("no line starting with %q in:\n%s", prefix, strings.Join(lines, "\n"))
	return ""
}

// TestReportHasNoTrailingNewline pins that Python returns "\n".join(lines) —
// the last line is the empty string the cost section appends, so the document
// ends with exactly one newline and no more.
func TestReportHasNoTrailingNewline(t *testing.T) {
	got := GenerateReport(schemas.NewCloudSecurityScanResult())
	if strings.HasSuffix(got, "\n\n") {
		t.Error("report must not end with a blank line plus a newline")
	}
	if !strings.HasSuffix(got, "\n") {
		t.Error("report's last joined element is \"\", so it must end with a newline")
	}
	if !strings.HasPrefix(got, "# CloudSecurity AF Infrastructure Security Report\n\n## Summary\n") {
		t.Errorf("unexpected header:\n%s", got[:80])
	}
}

// TestReportBranchFalsyArms pins `f"- Branch: ..." if result.branch else
// "- Branch: n/a"`: `branch` is `str | None`, so BOTH None and "" take the n/a
// arm — an empty string is falsy in Python but not nil in Go.
func TestReportBranchFalsyArms(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()

	if got := lineWithPrefix(t, reportOf(result), "- Branch:"); got != "- Branch: n/a" {
		t.Errorf("nil branch -> %q", got)
	}

	empty := ""
	result.Branch = &empty
	if got := lineWithPrefix(t, reportOf(result), "- Branch:"); got != "- Branch: n/a" {
		t.Errorf("empty branch -> %q, want the n/a arm (Python truthiness)", got)
	}

	main := "main"
	result.Branch = &main
	if got := lineWithPrefix(t, reportOf(result), "- Branch:"); got != "- Branch: `main`" {
		t.Errorf("populated branch -> %q", got)
	}
}

// TestReportTierNaming pins `'static' if tier == 1 else 'live' if tier == 2
// else 'deep'` — every other tier, including 0 and 9, reads "deep".
func TestReportTierNaming(t *testing.T) {
	for tier, want := range map[int]string{
		0: "- Tier: **0** (deep)",
		1: "- Tier: **1** (static)",
		2: "- Tier: **2** (live)",
		3: "- Tier: **3** (deep)",
		9: "- Tier: **9** (deep)",
	} {
		result := schemas.NewCloudSecurityScanResult()
		result.Tier = tier
		if got := lineWithPrefix(t, reportOf(result), "- Tier:"); got != want {
			t.Errorf("tier %d -> %q, want %q", tier, got, want)
		}
	}
}

// TestReportProvidersFallback pins `', '.join(providers) or 'none detected'`.
func TestReportProvidersFallback(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()
	if got := lineWithPrefix(t, reportOf(result), "- Providers:"); got != "- Providers: none detected" {
		t.Errorf("empty providers -> %q", got)
	}
	result.ProvidersDetected = []string{"aws", "gcp"}
	if got := lineWithPrefix(t, reportOf(result), "- Providers:"); got != "- Providers: aws, gcp" {
		t.Errorf("populated providers -> %q", got)
	}
}

// TestReportEmptySections pins the two "nothing to report" arms and that the
// conditional Drift/Compliance sections are absent when their guards are false.
func TestReportEmptySections(t *testing.T) {
	lines := reportOf(schemas.NewCloudSecurityScanResult())
	for _, want := range []string{"No findings.", "No multi-resource attack paths identified.", "  - n/a"} {
		if !containsLine(lines, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, unwanted := range []string{"## Drift Summary", "## Compliance"} {
		if containsLine(lines, unwanted) {
			t.Errorf("%q must be omitted when its guard is false", unwanted)
		}
	}
}

// TestReportDriftSectionGuard pins `if drift_resources > 0 or
// shadow_it_resources > 0` — EITHER counter alone brings the section in, and
// both numbers are always printed.
func TestReportDriftSectionGuard(t *testing.T) {
	cases := []struct{ drift, shadow int }{{1, 0}, {0, 1}, {2, 3}}
	for _, tc := range cases {
		result := schemas.NewCloudSecurityScanResult()
		result.DriftResources = tc.drift
		result.ShadowITResources = tc.shadow
		lines := reportOf(result)
		if !containsLine(lines, "## Drift Summary") {
			t.Fatalf("drift=%d shadow=%d: section missing", tc.drift, tc.shadow)
		}
		if !containsLine(lines, "- Drifted resources: **"+itoaTest(tc.drift)+"**") {
			t.Errorf("drift=%d: count line missing", tc.drift)
		}
		if !containsLine(lines, "- Shadow IT (cloud-only) resources: **"+itoaTest(tc.shadow)+"**") {
			t.Errorf("shadow=%d: count line missing", tc.shadow)
		}
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// TestReportNumberFormats pins the four format specs against CPython ground
// truth (verified with the venv: f"{v:.1f}" / f"{v:.2f}" / f"{v:.4f}").
// Python and Go both round half-to-even on the exact binary value, so a tie
// like 0.25 -> "0.2" must come out the same on both sides.
func TestReportNumberFormats(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()
	result.NoiseReductionPct = 0.25 // f"{0.25:.1f}" == "0.2"
	result.DurationSeconds = 0.35   // f"{0.35:.1f}" == "0.3"
	result.CostUSD = 0.00005        // f"{0.00005:.4f}" == "0.0001"
	result.AgentInvocations = 7
	// Go parity note: the untyped constant -0.0 is POSITIVE zero, so negative
	// zero has to be minted with Copysign — the fixture gets it from JSON.
	result.CostBreakdown = map[string]float64{"prove": 1e16, "recon": math.Copysign(0, -1)}

	lines := reportOf(result)
	for _, want := range []string{
		"- Noise reduction: **0.2%**",
		"- Duration: 0.3s",
		"- Agent invocations: 7",
		"- Cost: $0.0001",
		"  - prove: $10000000000000000.0000",
		"  - recon: $-0.0000",
	} {
		if !containsLine(lines, want) {
			t.Errorf("missing %q in:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}

// TestReportCostBreakdownUsesThePipelineOrder pins the Markdown report's phase
// order against Python's.
//
// orchestrator.py seeds `self.cost_breakdown = {phase: 0.0 for phase in
// self._PHASE_ORDER}` with `_PHASE_ORDER = ("recon","hunt","chain","prove",
// "remediate")` and only ever mutates existing keys, so
// `for phase, cost in result.cost_breakdown.items()` (report.py:67-69) always
// reads recon, hunt, chain, prove, remediate. Sorting a Go map instead printed
// chain, hunt, prove, recon, remediate.
func TestReportCostBreakdownUsesThePipelineOrder(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()
	// Built in a deliberately scrambled Go map — the order must come from
	// _PHASE_ORDER, not from the literal and not from sorting.
	result.CostBreakdown = map[string]float64{
		"prove": 0.4, "recon": 0.1, "remediate": 0.5, "chain": 0.3, "hunt": 0.2,
	}
	if got := strings.Join(costPhases(result), ","); got != "recon,hunt,chain,prove,remediate" {
		t.Fatalf("cost breakdown order = %s, want recon,hunt,chain,prove,remediate", got)
	}

	// A subset keeps its relative pipeline order.
	result.CostBreakdown = map[string]float64{"prove": 0.4, "recon": 0.1}
	if got := strings.Join(costPhases(result), ","); got != "recon,prove" {
		t.Fatalf("cost breakdown order = %s, want recon,prove", got)
	}

	// A key outside _PHASE_ORDER is unreachable on the live path; it lands
	// after the known phases, in code-point order, so the report stays
	// deterministic.
	result.CostBreakdown = map[string]float64{"zzz": 0.1, "prove": 0.4, "aaa": 0.2}
	if got := strings.Join(costPhases(result), ","); got != "prove,aaa,zzz" {
		t.Fatalf("cost breakdown order = %s, want prove,aaa,zzz", got)
	}
}

// costPhases reads the phase names out of the report's cost-breakdown bullets.
func costPhases(result schemas.CloudSecurityScanResult) []string {
	var seen []string
	for _, line := range reportOf(result) {
		if strings.HasPrefix(line, "  - ") && strings.Contains(line, "$") {
			seen = append(seen, strings.TrimPrefix(strings.Split(line, ":")[0], "  - "))
		}
	}
	return seen
}

// TestReportFindingOptionalLines pins every truthiness guard in
// _render_finding, one at a time.
func TestReportFindingOptionalLines(t *testing.T) {
	base := schemas.NewVerifiedFinding()
	base.ID = "f1"
	base.Title = "Open bucket"
	base.Verdict = schemas.VerdictConfirmed
	base.Severity = scoring.SeverityHigh
	base.Category = "public_exposure"
	base.HunterStrategy = "data"
	base.IaCFile = "s3.tf"
	base.IaCLine = 4
	// Verified against the venv: f"{8.005:.2f}" == "8.01" (8.005 is just ABOVE
	// the tie in binary), and Go's %.2f agrees. f"{2.675:.2f}" == "2.67" and
	// f"{0.125:.2f}" == "0.12" likewise match, so the two round identically.
	base.RiskScore = 8.005

	result := schemas.NewCloudSecurityScanResult()
	result.Findings = []schemas.VerifiedFinding{base}
	lines := reportOf(result)

	for _, want := range []string{
		"### Open bucket",
		"- ID: `f1`",
		"- Verdict: `confirmed` | Severity: `high`",
		"- Risk score: **8.01/10**",
		"- Category: `public_exposure` | Hunter: `data`",
		"- Location: `s3.tf:4`",
	} {
		if !containsLine(lines, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, unwanted := range []string{"- Description: ", "- Attack path: ", "- Drift detected: ", "- Compliance: ", "- Remediation: ", "```hcl"} {
		for _, line := range lines {
			if strings.HasPrefix(line, unwanted) {
				t.Errorf("bare finding must not emit %q (got %q)", unwanted, line)
			}
		}
	}

	// Now switch every optional on.
	path := schemas.NewAttackPath()
	path.Title = "ALB to bucket"
	drift := schemas.DriftedResource{ResourceID: "aws_s3_bucket.b", Significance: "critical"}
	downtime := "minutes"
	full := base
	full.Description = "acl is public-read"
	full.AttackPath = &path
	full.Drift = &drift
	full.ComplianceMappings = []string{"CIS-AWS-2.1.1", "SOC2"}
	full.Remediation = &schemas.RemediationSuggestion{
		Description:      "Set acl = private",
		BreakingChange:   true,
		DowntimeEstimate: &downtime,
	}
	full.ConfigSnippet = "acl = \"public-read\""

	result.Findings = []schemas.VerifiedFinding{full}
	lines = reportOf(result)
	for _, want := range []string{
		"- Description: acl is public-read",
		"- Attack path: **ALB to bucket**",
		"- Drift detected: `aws_s3_bucket.b` (critical)",
		"- Compliance: CIS-AWS-2.1.1, SOC2",
		"- Remediation: Set acl = private",
		"  - **WARNING: Breaking change**",
		"  - Downtime: minutes",
		"```hcl",
		"acl = \"public-read\"",
		"```",
	} {
		if !containsLine(lines, want) {
			t.Errorf("missing %q in:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}

// TestReportEmptyDowntimeIsSuppressed pins that `downtime_estimate` is a
// `str | None` guarded by truthiness: an EMPTY string is skipped, exactly like
// None.
func TestReportEmptyDowntimeIsSuppressed(t *testing.T) {
	empty := ""
	f := schemas.NewVerifiedFinding()
	f.Title = "T"
	f.Verdict = schemas.VerdictLikely
	f.Severity = scoring.SeverityLow
	f.Remediation = &schemas.RemediationSuggestion{Description: "d", DowntimeEstimate: &empty}

	result := schemas.NewCloudSecurityScanResult()
	result.Findings = []schemas.VerifiedFinding{f}
	for _, line := range reportOf(result) {
		if strings.HasPrefix(line, "  - Downtime:") {
			t.Fatalf("an empty downtime_estimate must be suppressed, got %q", line)
		}
	}
}

// TestReportAttackPathRendering pins _render_attack_path, including the two
// blast-radius guards and the em-dashed step line built from two adjacent
// f-strings.
func TestReportAttackPathRendering(t *testing.T) {
	path := schemas.NewAttackPath()
	path.ID = "p1"
	path.Title = "ALB to bucket"
	path.CombinedSeverity = scoring.SeverityCritical
	path.EntryPoint = "aws_lb.public"
	path.Target = "aws_s3_bucket.pii"
	path.FindingsInvolved = []string{"f1", "f2"}
	path.Steps = []schemas.AttackStep{
		{StepNumber: 1, ResourceID: "aws_lb.public", ResourceType: "aws_lb", Action: "Reach it", PermissionUsed: "0.0.0.0/0"},
	}

	result := schemas.NewCloudSecurityScanResult()
	result.AttackPaths = []schemas.AttackPath{path}
	lines := reportOf(result)

	for _, want := range []string{
		"### ALB to bucket",
		"- ID: `p1`",
		"- Combined severity: `critical`",
		"- Entry: `aws_lb.public` → Target: `aws_s3_bucket.pii`",
		"- Findings involved: `f1`, `f2`",
		"- Steps:",
		"  1. `aws_lb.public` (aws_lb) — Reach it via `0.0.0.0/0`",
	} {
		if !containsLine(lines, want) {
			t.Errorf("missing %q in:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	for _, unwanted := range []string{"- Blast radius — data stores:", "- Blast radius — compute:"} {
		for _, line := range lines {
			if strings.HasPrefix(line, unwanted) {
				t.Errorf("empty blast radius must not emit %q", unwanted)
			}
		}
	}

	path.BlastRadius.DataStoresReachable = []string{"s3://a", "s3://b"}
	path.BlastRadius.ComputeReachable = []string{"ecs/api"}
	result.AttackPaths = []schemas.AttackPath{path}
	lines = reportOf(result)
	if !containsLine(lines, "- Blast radius — data stores: s3://a, s3://b") {
		t.Error("missing the data-stores blast radius line")
	}
	if !containsLine(lines, "- Blast radius — compute: ecs/api") {
		t.Error("missing the compute blast radius line")
	}
}

// TestReportTimestampUsesIsoformat pins that the summary interpolates
// `result.timestamp.isoformat()`, i.e. the "+00:00" spelling.
func TestReportTimestampUsesIsoformat(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()
	result.Timestamp = schemas.NewTimestamp(time.Date(2026, 5, 6, 7, 8, 9, 123456000, time.UTC))
	want := "- Timestamp: `2026-05-06T07:08:09.123456+00:00`"
	if got := lineWithPrefix(t, reportOf(result), "- Timestamp:"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestRenderReportIsAnAlias pins render_report == generate_report.
func TestRenderReportIsAnAlias(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()
	if RenderReport(result) != GenerateReport(result) {
		t.Fatal("render_report must return exactly what generate_report returns")
	}
}
