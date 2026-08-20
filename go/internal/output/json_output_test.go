package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// Behaviour tests for output/json_output.py, derived from the Python source.
// The byte-level agreement is golden_test.go's job.

// TestGenerateJSONModesAreDifferentSerializers pins the single most surprising
// thing about generate_json: `pretty` does not reflow one document, it swaps
// the serializer. The compact form is pydantic's model_dump_json (no spaces,
// raw UTF-8, "…Z" datetimes); the pretty form is CPython's json.dumps of what
// json.loads made of it (indent 2, ensure_ascii, repr floats).
func TestGenerateJSONModesAreDifferentSerializers(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()
	result.Repository = "héllo — 世界"
	result.Timestamp = schemas.NewTimestamp(time.Date(2026, 5, 6, 7, 8, 9, 123456000, time.UTC))
	result.NoiseReductionPct = 1e-05

	compact := GenerateJSON(result, false)
	pretty := GenerateJSON(result, true)

	// Separators.
	if strings.Contains(compact, `": `) || strings.Contains(compact, ", \"") {
		t.Errorf("pydantic's spelling has no whitespace after separators:\n%s", compact)
	}
	if !strings.Contains(pretty, "\n  \"repository\": ") {
		t.Errorf("json.dumps(indent=2) spelling missing:\n%s", pretty[:200])
	}

	// ensure_ascii.
	if !strings.Contains(compact, "héllo — 世界") {
		t.Error("pydantic writes non-ASCII raw")
	}
	if strings.Contains(pretty, "héllo") || !strings.Contains(pretty, `\u00e9llo`) {
		t.Errorf("json.dumps escapes every non-ASCII rune; got %s", pretty[:200])
	}

	// Datetime spelling.
	if !strings.Contains(compact, `"2026-05-06T07:08:09.123456Z"`) {
		t.Errorf("pydantic writes the Z spelling:\n%s", compact)
	}
	if !strings.Contains(pretty, `"2026-05-06T07:08:09.123456Z"`) {
		t.Error("the pretty form re-reads pydantic's string verbatim, so it keeps the Z")
	}

	// Float spelling.
	if !strings.Contains(compact, `"noise_reduction_pct":0.00001`) {
		t.Errorf("pydantic renders 1e-05 as 0.00001:\n%s", compact)
	}
	if !strings.Contains(pretty, `"noise_reduction_pct": 1e-05`) {
		t.Error("json.dumps renders 1e-05 as 1e-05")
	}

	// Both must nonetheless describe the same document.
	var a, b any
	if err := json.Unmarshal([]byte(compact), &a); err != nil {
		t.Fatalf("compact is not valid JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(pretty), &b); err != nil {
		t.Fatalf("pretty is not valid JSON: %v", err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("the two spellings disagree about the document:\n %s\n %s", ja, jb)
	}
}

// TestGenerateJSONKeepsFieldOrder pins that the full dump follows pydantic's
// FIELD DECLARATION order, not alphabetical order — the Go struct's field order
// is the contract.
func TestGenerateJSONKeepsFieldOrder(t *testing.T) {
	got := GenerateJSON(schemas.NewCloudSecurityScanResult(), false)
	want := []string{"repository", "commit_sha", "branch", "timestamp", "depth_profile", "tier",
		"providers_detected", "findings", "attack_paths", "total_resources_scanned"}
	pos := -1
	for _, key := range want {
		at := strings.Index(got, `"`+key+`":`)
		if at < 0 {
			t.Fatalf("key %q missing from:\n%s", key, got)
		}
		if at < pos {
			t.Fatalf("key %q is out of declaration order in:\n%s", key, got)
		}
		pos = at
	}
}

// TestSummaryJSONShape pins generate_summary_json's key set and the derived
// values it computes rather than copies.
func TestSummaryJSONShape(t *testing.T) {
	path := schemas.NewAttackPath()
	path.ID = "p1"
	path.Title = "ALB to bucket"
	path.EntryPoint = "aws_lb.public"
	path.Target = "aws_s3_bucket.pii"
	path.CombinedSeverity = scoring.SeverityCritical
	path.FindingsInvolved = []string{"f1"}
	path.Steps = []schemas.AttackStep{{StepNumber: 1}, {StepNumber: 2}}

	drift := schemas.DriftedResource{ResourceID: "r", Significance: "high"}
	f := schemas.NewVerifiedFinding()
	f.ID = "f1"
	f.Title = "Open bucket"
	f.Severity = scoring.SeverityHigh
	f.Verdict = schemas.VerdictLikely
	f.RiskScore = 7.5
	f.Category = "public_exposure"
	f.IaCFile = "s3.tf"
	f.IaCLine = 4
	f.HunterStrategy = "data"
	f.AttackPath = &path
	f.Drift = &drift

	result := schemas.NewCloudSecurityScanResult()
	result.Repository = "org/repo"
	result.CommitSHA = "abc"
	result.Timestamp = schemas.NewTimestamp(time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC))
	result.DepthProfile = "standard"
	result.Tier = 2
	result.ProvidersDetected = []string{"aws"}
	result.Findings = []schemas.VerifiedFinding{f}
	result.AttackPaths = []schemas.AttackPath{path}
	result.TotalResourcesScanned = 12
	result.Confirmed, result.Likely, result.Inconclusive, result.NotExploitable = 0, 1, 0, 0
	result.NoiseReductionPct = 50.0
	result.BySeverity = map[string]int{"high": 1}
	result.DriftResources, result.ShadowITResources = 2, 1
	result.ComplianceFrameworksChecked = []string{"CIS-AWS"}
	result.DurationSeconds = 1.5
	result.CostUSD = 0.25
	result.CostBreakdown = map[string]float64{"hunt": 0.25}
	result.AgentInvocations = 9

	var doc map[string]any
	if err := json.Unmarshal([]byte(GenerateSummaryJSON(result)), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	topLevel := []string{"repository", "commit_sha", "timestamp", "depth_profile", "tier",
		"providers_detected", "summary", "findings", "attack_paths", "drift",
		"compliance_frameworks_checked", "performance"}
	for _, key := range topLevel {
		if _, ok := doc[key]; !ok {
			t.Errorf("summary is missing %q", key)
		}
	}
	if len(doc) != len(topLevel) {
		t.Errorf("summary has %d keys, want %d — an extra key is a parity break", len(doc), len(topLevel))
	}

	// The timestamp here is isoformat(), NOT pydantic's Z spelling.
	if got := doc["timestamp"]; got != "2026-05-06T07:08:09+00:00" {
		t.Errorf("timestamp = %v, want the isoformat spelling", got)
	}

	summary, _ := doc["summary"].(map[string]any)
	if got := summary["total_findings"]; got != float64(1) {
		t.Errorf("total_findings = %v, want 1 (len(findings), not a stored count)", got)
	}

	findings, _ := doc["findings"].([]any)
	first, _ := findings[0].(map[string]any)
	if first["has_attack_path"] != true || first["has_drift"] != true {
		t.Errorf("has_attack_path/has_drift = %v/%v, want true/true",
			first["has_attack_path"], first["has_drift"])
	}
	if first["severity"] != "high" || first["verdict"] != "likely" {
		t.Errorf("enums must be rendered as their values, got %v/%v", first["severity"], first["verdict"])
	}

	paths, _ := doc["attack_paths"].([]any)
	firstPath, _ := paths[0].(map[string]any)
	if got := firstPath["steps_count"]; got != float64(2) {
		t.Errorf("steps_count = %v, want 2 (len(steps), the steps themselves are omitted)", got)
	}
	if _, present := firstPath["steps"]; present {
		t.Error("the summary must not carry the full steps list")
	}
}

// TestSummaryJSONNilFlags pins that has_attack_path / has_drift are false when
// the pointers are nil (Python: `is not None`).
func TestSummaryJSONNilFlags(t *testing.T) {
	f := schemas.NewVerifiedFinding()
	f.Title = "T"
	f.Verdict = schemas.VerdictConfirmed
	f.Severity = scoring.SeverityLow

	result := schemas.NewCloudSecurityScanResult()
	result.Findings = []schemas.VerifiedFinding{f}

	var doc map[string]any
	if err := json.Unmarshal([]byte(GenerateSummaryJSON(result)), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	findings, _ := doc["findings"].([]any)
	first, _ := findings[0].(map[string]any)
	if first["has_attack_path"] != false || first["has_drift"] != false {
		t.Errorf("want false/false, got %v/%v", first["has_attack_path"], first["has_drift"])
	}
}

// TestSummaryJSONEmptyContainers pins that empty lists render as [] rather than
// null, which is what a nil Go slice would give.
func TestSummaryJSONEmptyContainers(t *testing.T) {
	got := GenerateSummaryJSON(schemas.NewCloudSecurityScanResult())
	for _, want := range []string{
		`"providers_detected": []`,
		`"findings": []`,
		`"attack_paths": []`,
		`"compliance_frameworks_checked": []`,
		`"by_severity": {}`,
		`"cost_breakdown": {}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in:\n%s", want, got)
		}
	}
}

// TestRenderJSONReturnsTheParsedDocument pins render_json.
func TestRenderJSONReturnsTheParsedDocument(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()
	result.Repository = "org/repo"
	result.Tier = 3

	got, err := RenderJSON(result)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if got["repository"] != "org/repo" {
		t.Errorf("repository = %v", got["repository"])
	}
	if got["tier"] != float64(3) {
		t.Errorf("tier = %v (encoding/json decodes every number as float64)", got["tier"])
	}
	if _, ok := got["findings"]; !ok {
		t.Error("render_json returns the FULL document, not the summary")
	}
}

// TestSummaryAndFullJSONUseThePythonDictOrder pins the two dict-typed result
// fields whose INSERTION order Python fixes and a Go map cannot carry.
//
// orchestrator.py:165 seeds `severity_counts = {s.value: 0 for s in Severity}`,
// and Severity is declared critical, high, medium, low, info (scoring.py:6-11),
// so json.dumps writes them in that order — never the alphabetical critical,
// high, info, low, medium. orchestrator.py:54,67 seeds cost_breakdown from
// _PHASE_ORDER, so it reads recon, hunt, chain, prove, remediate.
func TestSummaryAndFullJSONUseThePythonDictOrder(t *testing.T) {
	result := schemas.NewCloudSecurityScanResult()
	result.Repository = "/repo"
	result.BySeverity = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	result.CostBreakdown = map[string]float64{
		"remediate": 0.5, "prove": 0.4, "chain": 0.3, "hunt": 0.2, "recon": 0.1,
	}

	for name, body := range map[string]string{
		"summary": GenerateSummaryJSON(result),
		"full":    GenerateJSON(result, true),
	} {
		severities := dictKeyOrder(t, body, "by_severity")
		if got := strings.Join(severities, ","); got != "critical,high,medium,low,info" {
			t.Errorf("%s json by_severity order = %s, want critical,high,medium,low,info", name, got)
		}
		phases := dictKeyOrder(t, body, "cost_breakdown")
		if got := strings.Join(phases, ","); got != "recon,hunt,chain,prove,remediate" {
			t.Errorf("%s json cost_breakdown order = %s, want recon,hunt,chain,prove,remediate", name, got)
		}
	}
}

// dictKeyOrder reads the key order of the object that follows `"<field>": {`
// in an indented JSON document.
func dictKeyOrder(t *testing.T, body, field string) []string {
	t.Helper()
	idx := strings.Index(body, `"`+field+`": {`)
	if idx < 0 {
		t.Fatalf("no %q object in the document:\n%s", field, body)
	}
	rest := body[idx+len(`"`+field+`": {`):]
	end := strings.Index(rest, "}")
	if end < 0 {
		t.Fatalf("unterminated %q object", field)
	}
	var keys []string
	for _, line := range strings.Split(rest[:end], "\n") {
		line = strings.TrimSpace(line)
		key, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		keys = append(keys, strings.Trim(key, `"`))
	}
	return keys
}
