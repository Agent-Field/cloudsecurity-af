package output

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// This file ports src/cloudsecurity_af/output/report.py — the Markdown report.
//
// Python builds a []string of lines and returns "\n".join(lines), so the
// document has NO trailing newline. Every f-string below is transcribed
// verbatim, including the em dashes ("—", U+2014) in the attack-path step and
// blast-radius lines.
//
// Float spellings: Python's `:.1f` / `:.2f` / `:.4f` and Go's `%.1f` / `%.2f` /
// `%.4f` both round half-to-even against the exact binary value, so they agree
// digit for digit. (They differ only for ±Inf and NaN — "inf"/"nan" in Python,
// "+Inf"/"NaN" in Go — which no scan can produce for these fields.)

// GenerateReport ports generate_report.
func GenerateReport(result schemas.CloudSecurityScanResult) string {
	lines := []string{
		"# CloudSecurity AF Infrastructure Security Report",
		"",
	}
	lines = append(lines, renderSummary(result)...)
	lines = append(lines, "## Findings", "")

	if len(result.Findings) > 0 {
		for _, finding := range result.Findings {
			lines = append(lines, renderFinding(finding)...)
		}
	} else {
		lines = append(lines, "No findings.", "")
	}

	lines = append(lines, "## Attack Paths", "")
	if len(result.AttackPaths) > 0 {
		for _, path := range result.AttackPaths {
			lines = append(lines, renderAttackPath(path)...)
		}
	} else {
		lines = append(lines, "No multi-resource attack paths identified.", "")
	}

	if result.DriftResources > 0 || result.ShadowITResources > 0 {
		lines = append(lines,
			"## Drift Summary",
			"",
			fmt.Sprintf("- Drifted resources: **%d**", result.DriftResources),
			fmt.Sprintf("- Shadow IT (cloud-only) resources: **%d**", result.ShadowITResources),
			"",
		)
	}

	if len(result.ComplianceFrameworksChecked) > 0 {
		lines = append(lines,
			"## Compliance",
			"",
			"- Frameworks checked: "+strings.Join(result.ComplianceFrameworksChecked, ", "),
			"",
		)
	}

	lines = append(lines,
		"## Performance & Cost",
		"",
		fmt.Sprintf("- Duration: %.1fs", result.DurationSeconds),
		fmt.Sprintf("- Agent invocations: %d", result.AgentInvocations),
		fmt.Sprintf("- Cost: $%.4f", result.CostUSD),
		"- Cost breakdown:",
	)
	if len(result.CostBreakdown) > 0 {
		// Python parity: `for phase, cost in result.cost_breakdown.items()`
		// walks the dict in INSERTION order, and orchestrator.py seeds it from
		// _PHASE_ORDER — so the report always reads recon, hunt, chain, prove,
		// remediate, never the alphabetical chain, hunt, prove, recon,
		// remediate a Go map's sorted keys produce.
		for _, phase := range orderedPhaseKeys(result.CostBreakdown) {
			lines = append(lines, fmt.Sprintf("  - %s: $%.4f", phase, result.CostBreakdown[phase]))
		}
	} else {
		lines = append(lines, "  - n/a")
	}
	lines = append(lines, "")

	return strings.Join(lines, "\n")
}

// RenderReport ports render_report, the alias generate_report is exported under.
func RenderReport(result schemas.CloudSecurityScanResult) string {
	return GenerateReport(result)
}

// ---------------------------------------------------------------------------
// Section renderers
// ---------------------------------------------------------------------------

// renderSummary ports _render_summary.
func renderSummary(result schemas.CloudSecurityScanResult) []string {
	// Python parity: `f"- Branch: \`{branch}\`" if result.branch else "- Branch: n/a"`
	// — `branch` is `str | None`, so BOTH None and "" take the n/a arm.
	branch := "- Branch: n/a"
	if result.Branch != nil && *result.Branch != "" {
		branch = "- Branch: `" + *result.Branch + "`"
	}

	// Python parity: `'static' if tier == 1 else 'live' if tier == 2 else 'deep'`
	// — every tier that is neither 1 nor 2 (including 0 and 4) reads "deep".
	tierName := "deep"
	switch result.Tier {
	case 1:
		tierName = "static"
	case 2:
		tierName = "live"
	}

	// Python parity: `', '.join(providers) or 'none detected'` — an empty list
	// joins to "", which is falsy.
	providers := strings.Join(result.ProvidersDetected, ", ")
	if providers == "" {
		providers = "none detected"
	}

	return []string{
		"## Summary",
		"",
		"- Repository: `" + result.Repository + "`",
		"- Commit: `" + result.CommitSHA + "`",
		branch,
		"- Timestamp: `" + result.Timestamp.ISOFormat() + "`",
		"- Depth profile: `" + result.DepthProfile + "`",
		fmt.Sprintf("- Tier: **%d** (%s)", result.Tier, tierName),
		"- Providers: " + providers,
		fmt.Sprintf("- Resources scanned: **%d**", result.TotalResourcesScanned),
		fmt.Sprintf("- Findings: **%d** (confirmed: %d, likely: %d, inconclusive: %d, not exploitable: %d)",
			len(result.Findings), result.Confirmed, result.Likely, result.Inconclusive, result.NotExploitable),
		fmt.Sprintf("- Noise reduction: **%.1f%%**", result.NoiseReductionPct),
		"",
	}
}

// renderFinding ports _render_finding. Every optional line is guarded by
// Python's truthiness of the corresponding field: an empty string, an empty
// list and None are all skipped, while a model instance is always truthy.
func renderFinding(finding schemas.VerifiedFinding) []string {
	lines := []string{
		"### " + finding.Title,
		"",
		"- ID: `" + finding.ID + "`",
		"- Verdict: `" + string(finding.Verdict) + "` | Severity: `" + string(finding.Severity) + "`",
		fmt.Sprintf("- Risk score: **%.2f/10**", finding.RiskScore),
		"- Category: `" + finding.Category + "` | Hunter: `" + finding.HunterStrategy + "`",
		"- Location: `" + finding.IaCFile + ":" + strconv.Itoa(finding.IaCLine) + "`",
	}
	if finding.Description != "" {
		lines = append(lines, "- Description: "+finding.Description)
	}
	if finding.AttackPath != nil {
		lines = append(lines, "- Attack path: **"+finding.AttackPath.Title+"**")
	}
	if finding.Drift != nil {
		lines = append(lines, "- Drift detected: `"+finding.Drift.ResourceID+"` ("+finding.Drift.Significance+")")
	}
	if len(finding.ComplianceMappings) > 0 {
		lines = append(lines, "- Compliance: "+strings.Join(finding.ComplianceMappings, ", "))
	}
	if finding.Remediation != nil {
		lines = append(lines, "- Remediation: "+finding.Remediation.Description)
		if finding.Remediation.BreakingChange {
			lines = append(lines, "  - **WARNING: Breaking change**")
		}
		// Python parity: `if finding.remediation.downtime_estimate:` — a `str |
		// None` field, so an EMPTY string is skipped too.
		if d := finding.Remediation.DowntimeEstimate; d != nil && *d != "" {
			lines = append(lines, "  - Downtime: "+*d)
		}
	}
	if finding.ConfigSnippet != "" {
		lines = append(lines, "", "```hcl", finding.ConfigSnippet, "```")
	}
	return append(lines, "")
}

// renderAttackPath ports _render_attack_path.
func renderAttackPath(path schemas.AttackPath) []string {
	quoted := make([]string, 0, len(path.FindingsInvolved))
	for _, fid := range path.FindingsInvolved {
		quoted = append(quoted, "`"+fid+"`")
	}

	lines := []string{
		"### " + path.Title,
		"",
		"- ID: `" + path.ID + "`",
		"- Combined severity: `" + string(path.CombinedSeverity) + "`",
		"- Entry: `" + path.EntryPoint + "` → Target: `" + path.Target + "`",
		"- Findings involved: " + strings.Join(quoted, ", "),
		"- Steps:",
	}
	for _, step := range path.Steps {
		// Python parity: the two adjacent f-strings concatenate into one line.
		lines = append(lines, fmt.Sprintf("  %d. `%s` (%s) — %s via `%s`",
			step.StepNumber, step.ResourceID, step.ResourceType, step.Action, step.PermissionUsed))
	}
	if len(path.BlastRadius.DataStoresReachable) > 0 {
		lines = append(lines, "- Blast radius — data stores: "+
			strings.Join(path.BlastRadius.DataStoresReachable, ", "))
	}
	if len(path.BlastRadius.ComputeReachable) > 0 {
		lines = append(lines, "- Blast radius — compute: "+
			strings.Join(path.BlastRadius.ComputeReachable, ", "))
	}
	return append(lines, "")
}

// orderedPhaseKeys returns a cost_breakdown map's keys in Python's INSERTION
// order (schemas.CostBreakdownOrder), followed by any key outside that set in
// code-point order — a tail the live path cannot produce, kept deterministic.
func orderedPhaseKeys(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	seen := make(map[string]bool, len(schemas.CostBreakdownOrder))
	for _, phase := range schemas.CostBreakdownOrder {
		seen[phase] = true
		if _, present := m[phase]; present {
			out = append(out, phase)
		}
	}
	rest := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}
