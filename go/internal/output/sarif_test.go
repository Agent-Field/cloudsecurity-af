package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// Behaviour tests for output/sarif.py. src/cloudsecurity_af has no Python test
// file for the output package, so every assertion here is derived from the
// Python SOURCE's observable behaviour (the validation contract), not from the
// Go implementation. The byte-level agreement with Python is golden_test.go's
// job; this file pins the branches a fixture cannot reach and states them in
// terms a reader can check against sarif.py line by line.

// finding is a terse VerifiedFinding builder for the tables below.
func finding(mut func(*schemas.VerifiedFinding)) schemas.VerifiedFinding {
	f := schemas.VerifiedFinding{
		Title:              "T",
		Verdict:            schemas.VerdictConfirmed,
		Severity:           scoring.SeverityMedium,
		Category:           "cat",
		ComplianceMappings: []string{},
		Proof:              schemas.NewProof(),
		HunterStrategy:     "hunter",
	}
	if mut != nil {
		mut(&f)
	}
	return f
}

// resultOf wraps findings in a scan result with a fixed timestamp.
func resultOf(findings ...schemas.VerifiedFinding) schemas.CloudSecurityScanResult {
	r := schemas.NewCloudSecurityScanResult()
	r.Repository = "repo"
	r.Findings = findings
	return r
}

// parseSarif decodes GenerateSarif's output so a test can assert structure
// without hand-matching 6KB of text.
func parseSarif(t *testing.T, result schemas.CloudSecurityScanResult) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(GenerateSarif(result)), &doc); err != nil {
		t.Fatalf("GenerateSarif produced invalid JSON: %v", err)
	}
	return doc
}

func runOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly one run, got %#v", doc["runs"])
	}
	run, _ := runs[0].(map[string]any)
	return run
}

// TestSarifDropsNotExploitable pins the noise reduction: a not_exploitable
// finding appears in neither the results NOR the rules.
func TestSarifDropsNotExploitable(t *testing.T) {
	kept := finding(func(f *schemas.VerifiedFinding) {
		f.SARIFRuleID = "rule/kept"
	})
	dropped := finding(func(f *schemas.VerifiedFinding) {
		f.Verdict = schemas.VerdictNotExploitable
		f.SARIFRuleID = "rule/dropped"
	})

	run := runOf(t, parseSarif(t, resultOf(kept, dropped)))
	results, _ := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if got := GenerateSarif(resultOf(kept, dropped)); strings.Contains(got, "rule/dropped") {
		t.Error("a not_exploitable finding must not contribute a rule")
	}
}

// TestSarifRuleIDFallback pins `finding.sarif_rule_id or
// f"cloudsecurity/{hunter_strategy}/{category}"`, and that the SAME expression
// is used for the rule and for the result (so they always agree).
func TestSarifRuleIDFallback(t *testing.T) {
	f := finding(func(f *schemas.VerifiedFinding) {
		f.SARIFRuleID = ""
		f.HunterStrategy = "iam"
		f.Category = "overprivilege"
	})
	if got, want := sarifRuleID(f), "cloudsecurity/iam/overprivilege"; got != want {
		t.Fatalf("sarifRuleID = %q, want %q", got, want)
	}

	run := runOf(t, parseSarif(t, resultOf(f)))
	results, _ := run["results"].([]any)
	first, _ := results[0].(map[string]any)
	if got := first["ruleId"]; got != "cloudsecurity/iam/overprivilege" {
		t.Fatalf("result ruleId = %v", got)
	}
	tool, _ := run["tool"].(map[string]any)
	driver, _ := tool["driver"].(map[string]any)
	rules, _ := driver["rules"].([]any)
	rule, _ := rules[0].(map[string]any)
	if got := rule["id"]; got != "cloudsecurity/iam/overprivilege" {
		t.Fatalf("rule id = %v", got)
	}
}

// TestSarifRulesAreSortedByID pins Python's `sorted(rules_by_id.items())`.
func TestSarifRulesAreSortedByID(t *testing.T) {
	mk := func(id string) schemas.VerifiedFinding {
		return finding(func(f *schemas.VerifiedFinding) { f.SARIFRuleID = id })
	}
	run := runOf(t, parseSarif(t, resultOf(mk("z/last"), mk("a/first"), mk("m/middle"))))
	tool, _ := run["tool"].(map[string]any)
	driver, _ := tool["driver"].(map[string]any)
	rules, _ := driver["rules"].([]any)

	var ids []string
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		ids = append(ids, rule["id"].(string))
	}
	want := []string{"a/first", "m/middle", "z/last"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("rule ids = %v, want %v", ids, want)
	}
}

// TestMaxLevelKeepsFirstMaximum pins Python's max(): on a tie it returns the
// FIRST element holding the maximum key, so two "error" severities resolve to
// the first one's level and a later equal-ranked entry cannot displace it.
func TestMaxLevelKeepsFirstMaximum(t *testing.T) {
	critical := finding(func(f *schemas.VerifiedFinding) { f.Severity = scoring.SeverityCritical })
	high := finding(func(f *schemas.VerifiedFinding) { f.Severity = scoring.SeverityHigh })
	low := finding(func(f *schemas.VerifiedFinding) { f.Severity = scoring.SeverityLow })

	if got := maxLevel([]schemas.VerifiedFinding{low, critical, high}); got != "error" {
		t.Fatalf("maxLevel = %q, want error", got)
	}
	if got := maxLevel([]schemas.VerifiedFinding{low}); got != "note" {
		t.Fatalf("maxLevel(single low) = %q, want note", got)
	}
}

// TestMaxPrecisionKeepsFirstMaximum is the same contract for verdicts.
func TestMaxPrecisionKeepsFirstMaximum(t *testing.T) {
	confirmed := finding(func(f *schemas.VerifiedFinding) { f.Verdict = schemas.VerdictConfirmed })
	likely := finding(func(f *schemas.VerifiedFinding) { f.Verdict = schemas.VerdictLikely })
	inconclusive := finding(func(f *schemas.VerifiedFinding) { f.Verdict = schemas.VerdictInconclusive })

	if got := maxPrecision([]schemas.VerifiedFinding{inconclusive, confirmed, likely}); got != "very-high" {
		t.Fatalf("maxPrecision = %q, want very-high", got)
	}
	if got := maxPrecision([]schemas.VerifiedFinding{inconclusive}); got != "medium" {
		t.Fatalf("maxPrecision(inconclusive) = %q, want medium", got)
	}
}

// TestSeverityAndPrecisionDefaults pins the `.get(..., default)` arms. A
// validated model cannot hold an out-of-enum value, but the port must behave
// the same if one ever arrives over the wire.
func TestSeverityAndPrecisionDefaults(t *testing.T) {
	if got := severityToLevelOf("purple"); got != "warning" {
		t.Fatalf("severityToLevelOf(unknown) = %q, want warning", got)
	}
	f := finding(func(f *schemas.VerifiedFinding) { f.Verdict = schemas.Verdict("mystery") })
	if got := precisionOf(f); got != "medium" {
		t.Fatalf("precisionOf(unknown) = %q, want medium", got)
	}
}

// TestFormatSecuritySeverityClamps pins _format_security_severity: clamp to
// [0, 10], one decimal, half-to-even at the tie.
func TestFormatSecuritySeverityClamps(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{-3, "0.0"},
		{0, "0.0"},
		{7.25, "7.2"},  // 7.25 is exactly representable -> ties to even
		{7.35, "7.3"},  // 7.35 is just below the tie in binary
		{9.99, "10.0"}, // rounds up, still within the clamp
		{10, "10.0"},
		{42, "10.0"},
	}
	for _, tc := range cases {
		if got := formatSecuritySeverity(tc.in); got != tc.want {
			t.Errorf("formatSecuritySeverity(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRuleName pins _rule_name, including the "_" -> "-" fold, the
// capitalize()-lowercases-the-rest rule, and the "CloudSecurityRule" fallback.
func TestRuleName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cloudsecurity/iam/public_bucket", "PublicBucket"},
		{"cloudsecurity/data/PUBLIC-exposure_v2", "PublicExposureV2"},
		{"simple", "Simple"},
		{"a/b/c--d", "CD"},
		{"trailing/", "CloudSecurityRule"},
		{"", "CloudSecurityRule"},
		{"a/---", "CloudSecurityRule"},
		{"pfx/iamROLE", "Iamrole"},
	}
	for _, tc := range cases {
		if got := ruleName(tc.in); got != tc.want {
			t.Errorf("ruleName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMessageTextFallsBackToTitle pins _message_text: "[VERDICT] title: desc",
// with the title standing in for an empty description.
func TestMessageTextFallsBackToTitle(t *testing.T) {
	f := finding(func(f *schemas.VerifiedFinding) {
		f.Title = "Open bucket"
		f.Description = ""
		f.Verdict = schemas.VerdictLikely
	})
	if got, want := messageText(f), "[LIKELY] Open bucket: Open bucket"; got != want {
		t.Fatalf("messageText = %q, want %q", got, want)
	}
	f.Description = "acl is public-read"
	if got, want := messageText(f), "[LIKELY] Open bucket: acl is public-read"; got != want {
		t.Fatalf("messageText = %q, want %q", got, want)
	}
}

// TestPhysicalLocation pins the line floor, the "unknown" uri fallback and the
// conditional snippet sub-object.
func TestPhysicalLocation(t *testing.T) {
	bare := finding(func(f *schemas.VerifiedFinding) {
		f.IaCFile = ""
		f.IaCLine = 0
		f.ConfigSnippet = ""
	})
	loc := physicalLocation(bare)
	artifact, ok := loc.Get("artifactLocation")
	if !ok {
		t.Fatal("no artifactLocation")
	}
	uri, _ := artifact.(obj).Get("uri")
	if uri != "unknown" {
		t.Fatalf("uri = %v, want unknown", uri)
	}
	region, _ := loc.Get("region")
	startLine, _ := region.(obj).Get("startLine")
	if startLine != 1 {
		t.Fatalf("startLine = %v, want 1 (max(iac_line, 1))", startLine)
	}
	if _, present := region.(obj).Get("snippet"); present {
		t.Error("an empty config_snippet must not add a snippet object")
	}

	withSnippet := finding(func(f *schemas.VerifiedFinding) {
		f.IaCFile = "main.tf"
		f.IaCLine = 9
		f.ConfigSnippet = "acl = \"public-read\""
	})
	region2, _ := physicalLocation(withSnippet).Get("region")
	snippet, present := region2.(obj).Get("snippet")
	if !present {
		t.Fatal("expected a snippet object")
	}
	text, _ := snippet.(obj).Get("text")
	if text != "acl = \"public-read\"" {
		t.Fatalf("snippet text = %v", text)
	}
}

// TestResultTagsAreDedupedAndSorted pins _result_tags / _base_tags:
// "security" and "infrastructure" always, plus category, hunter strategy and a
// "compliance:<id>" per mapping — as a sorted set, so a category that equals
// the hunter strategy collapses to one tag.
func TestResultTagsAreDedupedAndSorted(t *testing.T) {
	f := finding(func(f *schemas.VerifiedFinding) {
		f.Category = "iam"
		f.HunterStrategy = "iam"
		f.ComplianceMappings = []string{"CIS-AWS-1.4", "CIS-AWS-1.4", "SOC2"}
	})
	got := resultTags(f)
	want := []string{"compliance:CIS-AWS-1.4", "compliance:SOC2", "iam", "infrastructure", "security"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("resultTags = %v, want %v", got, want)
	}
}

// TestAggregateRuleTagsUnionsEveryFinding pins _aggregate_rule_tags.
func TestAggregateRuleTagsUnionsEveryFinding(t *testing.T) {
	a := finding(func(f *schemas.VerifiedFinding) {
		f.Category = "net"
		f.HunterStrategy = "network"
		f.ComplianceMappings = []string{"CIS-AWS-5.2"}
	})
	b := finding(func(f *schemas.VerifiedFinding) {
		f.Category = "data"
		f.HunterStrategy = "data"
	})
	got := aggregateRuleTags([]schemas.VerifiedFinding{a, b})
	want := []string{"compliance:CIS-AWS-5.2", "data", "infrastructure", "net", "network", "security"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("aggregateRuleTags = %v, want %v", got, want)
	}
}

// TestEmptyTagSetRendersAsList guards against the nil-slice-is-null trap: a
// finding with no tags cannot exist (two are constant), but sortedKeys must
// never hand pyfmt.Dumps a nil.
func TestEmptyTagSetRendersAsList(t *testing.T) {
	if got := sortedKeys(map[string]struct{}{}); got == nil {
		t.Fatal("sortedKeys returned nil; an empty tag set must render as []")
	}
}

// TestRuleAggregatesMaxSecuritySeverity pins
// `max(f.sarif_security_severity for f in findings)` on the RULE, while each
// RESULT keeps its own score.
func TestRuleAggregatesMaxSecuritySeverity(t *testing.T) {
	low := finding(func(f *schemas.VerifiedFinding) {
		f.SARIFRuleID = "r"
		f.SARIFSecuritySeverity = 2.5
	})
	high := finding(func(f *schemas.VerifiedFinding) {
		f.SARIFRuleID = "r"
		f.SARIFSecuritySeverity = 8.5
	})
	rule := buildRule("r", []schemas.VerifiedFinding{low, high})
	props, _ := rule.Get("properties")
	sev, _ := props.(obj).Get("security-severity")
	if sev != "8.5" {
		t.Fatalf("rule security-severity = %v, want 8.5", sev)
	}

	res := buildResult(low)
	rprops, _ := res.Get("properties")
	rsev, _ := rprops.(obj).Get("security-severity")
	if rsev != "2.5" {
		t.Fatalf("result security-severity = %v, want 2.5", rsev)
	}
}

// TestRuleFullDescriptionFallsBackToTitle pins
// `representative.description or representative.title`.
func TestRuleFullDescriptionFallsBackToTitle(t *testing.T) {
	f := finding(func(f *schemas.VerifiedFinding) {
		f.Title = "Only a title"
		f.Description = ""
	})
	rule := buildRule("r", []schemas.VerifiedFinding{f})
	full, _ := rule.Get("fullDescription")
	text, _ := full.(obj).Get("text")
	if text != "Only a title" {
		t.Fatalf("fullDescription.text = %v, want the title", text)
	}
	short, _ := rule.Get("shortDescription")
	stext, _ := short.(obj).Get("text")
	if stext != "Only a title" {
		t.Fatalf("shortDescription.text = %v", stext)
	}
}

// TestAttackPathPropertyIsAppendedLast pins a subtle Python parity detail:
// _build_result assigns result["properties"]["cloudsecurity/attack_path"] AFTER
// the dict literal is built, so the key lands after "tags" — not next to the
// other cloudsecurity/* keys. The key order is observable in the artifact.
func TestAttackPathPropertyIsAppendedLast(t *testing.T) {
	path := schemas.NewAttackPath()
	path.Title = "Public ALB to bucket"
	f := finding(func(f *schemas.VerifiedFinding) { f.AttackPath = &path })

	props, _ := buildResult(f).Get("properties")
	pairs := props.(obj)
	last := pairs[len(pairs)-1]
	if last.K != "cloudsecurity/attack_path" {
		var keys []string
		for _, p := range pairs {
			keys = append(keys, p.K)
		}
		t.Fatalf("last properties key = %q, want cloudsecurity/attack_path (order: %v)", last.K, keys)
	}
	if last.V != "Public ALB to bucket" {
		t.Fatalf("attack_path value = %v", last.V)
	}

	// Without an attack path the key is absent entirely.
	plain, _ := buildResult(finding(nil)).Get("properties")
	if _, present := plain.(obj).Get("cloudsecurity/attack_path"); present {
		t.Error("a finding with no attack path must not carry the key")
	}
}

// TestAutomationDetailsUsesIsoformat pins that the run id interpolates
// `result.timestamp.isoformat()` — the "+00:00" spelling, NOT pydantic's "Z".
func TestAutomationDetailsUsesIsoformat(t *testing.T) {
	result := resultOf()
	result.Repository = "org/repo"
	run := runOf(t, parseSarif(t, result))
	details, _ := run["automationDetails"].(map[string]any)
	id, _ := details["id"].(string)
	want := "cloudsecurity-af/scan/org/repo/" + result.Timestamp.ISOFormat()
	if id != want {
		t.Fatalf("automationDetails.id = %q, want %q", id, want)
	}
	if strings.HasSuffix(id, "Z") {
		t.Error("isoformat() never emits the Z spelling")
	}
}

// TestRenderSarifIsAnAlias pins render_sarif == generate_sarif.
func TestRenderSarifIsAnAlias(t *testing.T) {
	result := resultOf(finding(nil))
	if RenderSarif(result) != GenerateSarif(result) {
		t.Fatal("render_sarif must return exactly what generate_sarif returns")
	}
}
