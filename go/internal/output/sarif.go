// Package output ports src/cloudsecurity_af/output: the three artifact
// generators a CloudSecurity scan can emit — the SARIF 2.1.0 document, the
// full/summary JSON, and the Markdown report.
//
// Only generate_sarif is wired into the live pipeline
// (orchestrator.py:211 `result.sarif = generate_sarif(result)`); the rest are
// ported for 1:1 completeness, since the Python module exports them.
//
// Every generator's bytes are a contract with a third party — a SARIF uploader,
// a diffing reviewer, an API client — so golden_test.go compares each one
// byte-for-byte against the Python original over a shared fixture. That is why
// nothing here uses encoding/json: JSON goes through pyfmt.Dumps (CPython's
// json.dumps) or pydanticDumps (pydantic's model_dump_json), and every float
// through pyfmt/pydantic float formatting.
package output

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// obj is a Python dict literal: an ordered key/value sequence, rendered in
// insertion order by pyfmt.Dumps. Key order is part of every artifact this
// package writes, so no generator may build a Go map for a JSON object whose
// Python spelling is a literal.
type obj = pyfmt.Ordered

// pythonPackageVersion mirrors `src/cloudsecurity_af/__init__.py::__version__`,
// which sarif.py stamps into the SARIF driver as `semanticVersion`. It is
// duplicated rather than derived because the Go binary has no import of the
// Python package; bump it together with the Python one.
const pythonPackageVersion = "0.1.0"

// severityToLevel ports _SEVERITY_TO_LEVEL.
var severityToLevel = map[string]string{
	"critical": "error",
	"high":     "error",
	"medium":   "warning",
	"low":      "note",
	"info":     "note",
}

// levelRank ports _LEVEL_RANK.
var levelRank = map[string]int{"error": 3, "warning": 2, "note": 1}

// verdictToPrecision ports _VERDICT_TO_PRECISION.
var verdictToPrecision = map[string]string{
	"confirmed":       "very-high",
	"likely":          "high",
	"inconclusive":    "medium",
	"not_exploitable": "low",
}

// precisionRank ports _PRECISION_RANK.
var precisionRank = map[string]int{"very-high": 4, "high": 3, "medium": 2, "low": 1}

// GenerateSarif ports output/sarif.py generate_sarif: the SARIF 2.1.0 document
// for one CloudSecurity scan result, serialised with
// `json.dumps(sarif, indent=2)`.
//
// Findings whose verdict is "not_exploitable" are dropped entirely — from the
// results AND from the rules — which is what makes the SARIF artifact the
// "signal only" view of a scan.
//
// The key order below is the Python dict literal's order and is part of the
// artifact, hence obj rather than a map.
func GenerateSarif(result schemas.CloudSecurityScanResult) string {
	included := make([]schemas.VerifiedFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if finding.Verdict != schemas.VerdictNotExploitable {
			included = append(included, finding)
		}
	}

	results := make([]any, 0, len(included))
	for _, finding := range included {
		results = append(results, buildResult(finding))
	}

	sarif := obj{
		{K: "$schema", V: "https://json.schemastore.org/sarif-2.1.0.json"},
		{K: "version", V: "2.1.0"},
		{K: "runs", V: []any{
			obj{
				{K: "tool", V: buildToolSection(included)},
				{K: "results", V: results},
				{K: "automationDetails", V: obj{
					{K: "id", V: fmt.Sprintf("cloudsecurity-af/scan/%s/%s",
						result.Repository, result.Timestamp.ISOFormat())},
				}},
			},
		}},
	}
	return pyfmt.Dumps(sarif, 2)
}

// RenderSarif ports render_sarif, the alias generate_sarif is exported under.
func RenderSarif(result schemas.CloudSecurityScanResult) string {
	return GenerateSarif(result)
}

// ---------------------------------------------------------------------------
// Tool / Rules
// ---------------------------------------------------------------------------

// buildToolSection ports _build_tool_section: one rule per distinct rule id, in
// sorted rule-id order (Python's `sorted(rules_by_id.items())`).
//
// Python parity: the rule id falls back to
// "cloudsecurity/<hunter_strategy>/<category>" whenever sarif_rule_id is empty,
// and the SAME expression is recomputed in _build_result — so a finding always
// lands under the rule it declares.
func buildToolSection(findings []schemas.VerifiedFinding) obj {
	rulesByID := map[string][]schemas.VerifiedFinding{}
	for _, finding := range findings {
		id := sarifRuleID(finding)
		rulesByID[id] = append(rulesByID[id], finding)
	}
	ruleIDs := make([]string, 0, len(rulesByID))
	for ruleID := range rulesByID {
		ruleIDs = append(ruleIDs, ruleID)
	}
	// sorted() on (key, value) tuples compares the keys first, and the keys are
	// unique, so this is a plain key sort. Go's byte order over valid UTF-8 is
	// Python's code-point order.
	sort.Strings(ruleIDs)

	rules := make([]any, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		rules = append(rules, buildRule(ruleID, rulesByID[ruleID]))
	}

	return obj{
		{K: "driver", V: obj{
			{K: "name", V: "CloudSecurity AF"},
			{K: "semanticVersion", V: pythonPackageVersion},
			{K: "informationUri", V: "https://github.com/Agent-Field/cloudsecurity-af"},
			{K: "rules", V: rules},
		}},
	}
}

// buildRule ports _build_rule. The FIRST finding carrying the rule id supplies
// the human-readable text; level, security-severity, precision and tags are
// aggregated over every finding that shares the id.
func buildRule(ruleID string, findings []schemas.VerifiedFinding) obj {
	representative := findings[0]

	// max(f.sarif_security_severity for f in findings)
	maxScore := findings[0].SARIFSecuritySeverity
	for _, finding := range findings[1:] {
		if finding.SARIFSecuritySeverity > maxScore {
			maxScore = finding.SARIFSecuritySeverity
		}
	}

	// Python parity: `representative.description or representative.title` —
	// an empty description falls back to the title.
	full := representative.Description
	if full == "" {
		full = representative.Title
	}

	return obj{
		{K: "id", V: ruleID},
		{K: "name", V: ruleName(ruleID)},
		// Python parity: f"{representative.title}" is just the title.
		{K: "shortDescription", V: obj{{K: "text", V: representative.Title}}},
		{K: "fullDescription", V: obj{{K: "text", V: full}}},
		{K: "defaultConfiguration", V: obj{{K: "level", V: maxLevel(findings)}}},
		{K: "properties", V: obj{
			{K: "precision", V: maxPrecision(findings)},
			{K: "security-severity", V: formatSecuritySeverity(maxScore)},
			{K: "tags", V: aggregateRuleTags(findings)},
		}},
	}
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

// buildResult ports _build_result: one SARIF result per included finding.
func buildResult(finding schemas.VerifiedFinding) obj {
	properties := obj{
		{K: "security-severity", V: formatSecuritySeverity(finding.SARIFSecuritySeverity)},
		{K: "cloudsecurity/verdict", V: string(finding.Verdict)},
		{K: "cloudsecurity/risk_score", V: finding.RiskScore},
		{K: "cloudsecurity/hunter_strategy", V: finding.HunterStrategy},
		{K: "cloudsecurity/category", V: finding.Category},
		{K: "cloudsecurity/compliance", V: finding.ComplianceMappings},
		{K: "tags", V: resultTags(finding)},
	}
	if finding.AttackPath != nil {
		// Python parity: this key is ASSIGNED after the literal is built, so it
		// lands LAST in the properties object — after "tags", not next to the
		// other cloudsecurity/* keys.
		properties = append(properties, pyfmt.KV{
			K: "cloudsecurity/attack_path", V: finding.AttackPath.Title,
		})
	}

	return obj{
		{K: "ruleId", V: sarifRuleID(finding)},
		{K: "level", V: severityToLevelOf(string(finding.Severity))},
		{K: "message", V: obj{{K: "text", V: messageText(finding)}}},
		{K: "locations", V: []any{obj{{K: "physicalLocation", V: physicalLocation(finding)}}}},
		{K: "partialFingerprints", V: obj{
			{K: "primaryLocationLineHash", V: finding.Fingerprint},
		}},
		{K: "properties", V: properties},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sarifRuleID ports the `finding.sarif_rule_id or f"cloudsecurity/{...}/{...}"`
// expression that _build_tool_section and _build_result each spell out.
func sarifRuleID(finding schemas.VerifiedFinding) string {
	if finding.SARIFRuleID != "" {
		return finding.SARIFRuleID
	}
	return "cloudsecurity/" + finding.HunterStrategy + "/" + finding.Category
}

// messageText ports _message_text: "[VERDICT] title: description", with the
// title standing in for an empty description.
func messageText(finding schemas.VerifiedFinding) string {
	desc := finding.Description
	if desc == "" {
		desc = finding.Title
	}
	return "[" + strings.ToUpper(string(finding.Verdict)) + "] " + finding.Title + ": " + desc
}

// physicalLocation ports _physical_location. The snippet sub-object appears
// only for a finding that carries one, and iac_line is floored at 1 because
// SARIF has no line 0.
func physicalLocation(finding schemas.VerifiedFinding) obj {
	startLine := finding.IaCLine
	if startLine < 1 {
		startLine = 1
	}
	region := obj{{K: "startLine", V: startLine}}
	if finding.ConfigSnippet != "" {
		region = append(region, pyfmt.KV{
			K: "snippet", V: obj{{K: "text", V: finding.ConfigSnippet}},
		})
	}

	uri := finding.IaCFile
	if uri == "" {
		uri = "unknown"
	}
	return obj{
		{K: "artifactLocation", V: obj{
			{K: "uri", V: uri},
			{K: "uriBaseId", V: "%SRCROOT%"},
		}},
		{K: "region", V: region},
	}
}

// severityToLevelOf ports _severity_to_level: an unknown severity is "warning".
func severityToLevelOf(severity string) string {
	if level, ok := severityToLevel[severity]; ok {
		return level
	}
	return "warning"
}

// maxLevel ports _max_level. Python's max() returns the FIRST element holding
// the maximum key, which the strict `>` comparison reproduces.
func maxLevel(findings []schemas.VerifiedFinding) string {
	best := severityToLevelOf(string(findings[0].Severity))
	for _, finding := range findings[1:] {
		level := severityToLevelOf(string(finding.Severity))
		if levelRank[level] > levelRank[best] {
			best = level
		}
	}
	return best
}

// maxPrecision ports _max_precision, with the same first-max-wins semantics.
func maxPrecision(findings []schemas.VerifiedFinding) string {
	best := precisionOf(findings[0])
	for _, finding := range findings[1:] {
		p := precisionOf(finding)
		if precisionRank[p] > precisionRank[best] {
			best = p
		}
	}
	return best
}

// precisionOf ports `_VERDICT_TO_PRECISION.get(f.verdict.value, "medium")`.
func precisionOf(finding schemas.VerifiedFinding) string {
	if p, ok := verdictToPrecision[string(finding.Verdict)]; ok {
		return p
	}
	return "medium"
}

// formatSecuritySeverity ports _format_security_severity: the score clamped to
// [0, 10] and rendered with one decimal. Go's %.1f and Python's :.1f both round
// half-to-even on the exact binary value, so the two agree bit for bit.
func formatSecuritySeverity(score float64) string {
	bounded := score
	if bounded < 0 {
		bounded = 0
	}
	if bounded > 10 {
		bounded = 10
	}
	return fmt.Sprintf("%.1f", bounded)
}

// aggregateRuleTags ports _aggregate_rule_tags: the sorted union of every
// finding's base tags.
func aggregateRuleTags(findings []schemas.VerifiedFinding) []string {
	seen := map[string]struct{}{}
	for _, finding := range findings {
		for _, tag := range baseTags(finding) {
			seen[tag] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

// resultTags ports _result_tags: one finding's base tags, deduplicated and
// sorted.
func resultTags(finding schemas.VerifiedFinding) []string {
	seen := map[string]struct{}{}
	for _, tag := range baseTags(finding) {
		seen[tag] = struct{}{}
	}
	return sortedKeys(seen)
}

// baseTags ports _base_tags. The order here does not survive (both callers
// sort), but it is kept identical to Python so a future caller that does not
// sort behaves the same.
func baseTags(finding schemas.VerifiedFinding) []string {
	tags := []string{"security", "infrastructure", finding.Category, finding.HunterStrategy}
	for _, mapping := range finding.ComplianceMappings {
		tags = append(tags, "compliance:"+mapping)
	}
	return tags
}

// sortedKeys ports `sorted(set(...))`: a deterministic, code-point-ordered list.
// It always returns a non-nil slice so an empty tag set renders as [] rather
// than null.
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ruleName ports _rule_name: the last "/"-separated segment of the rule id,
// with "_" folded to "-", split on "-", each non-empty chunk capitalized and
// concatenated — "cloudsecurity/iam/public_bucket" becomes "PublicBucket" —
// falling back to "CloudSecurityRule" when that yields nothing.
func ruleName(ruleID string) string {
	segments := strings.Split(ruleID, "/")
	rawName := strings.ReplaceAll(segments[len(segments)-1], "_", "-")
	var b strings.Builder
	for _, chunk := range strings.Split(rawName, "-") {
		if chunk == "" {
			continue
		}
		b.WriteString(pyCapitalize(chunk))
	}
	if b.Len() == 0 {
		return "CloudSecurityRule"
	}
	return b.String()
}

// pyCapitalize ports Python's str.capitalize(): the first character is
// upper-cased and EVERY other character is lower-cased ("iamROLE" -> "Iamrole").
func pyCapitalize(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(s)
	out := make([]rune, 0, len(runes))
	out = append(out, unicode.ToUpper(runes[0]))
	for _, r := range runes[1:] {
		out = append(out, unicode.ToLower(r))
	}
	return string(out)
}
