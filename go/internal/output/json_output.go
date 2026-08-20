package output

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// This file ports src/cloudsecurity_af/output/json_output.py.

// GenerateJSON ports generate_json: the full serialization of a scan result.
//
//	full_json = result.model_dump_json()
//	if not pretty: return full_json
//	return json.dumps(json.loads(full_json), indent=2)
//
// The two modes are NOT the same document reflowed — they are two different
// serializers (see pydantic.go). pretty=false returns pydantic's own compact
// spelling, raw UTF-8 and all; pretty=true returns what CPython's json.dumps
// makes of it after a round-trip, which re-escapes every non-ASCII character
// and re-renders every float as repr(float).
//
// Python parity: `pretty` has no Go default — Python's is True. Callers that
// mirror `generate_json(result)` must pass true.
func GenerateJSON(result schemas.CloudSecurityScanResult, pretty bool) string {
	tree := pyTree(result)
	if !pretty {
		return pydanticDumps(tree)
	}
	return pyfmt.Dumps(tree, 2)
}

// GenerateSummaryJSON ports generate_summary_json: the compact summary with
// statistics and one line per finding / attack path.
//
// It is a hand-built dict, not a model dump, so the key order below is the
// Python literal's order and part of the artifact.
//
// Python parity: `result.timestamp.isoformat()` here is the ISO spelling with a
// numeric UTC offset ("+00:00"), NOT the "Z" spelling model_dump_json uses.
func GenerateSummaryJSON(result schemas.CloudSecurityScanResult) string {
	findings := make([]any, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, obj{
			{K: "id", V: f.ID},
			{K: "title", V: f.Title},
			{K: "severity", V: string(f.Severity)},
			{K: "verdict", V: string(f.Verdict)},
			{K: "risk_score", V: f.RiskScore},
			{K: "category", V: f.Category},
			{K: "iac_file", V: f.IaCFile},
			{K: "iac_line", V: f.IaCLine},
			{K: "hunter_strategy", V: f.HunterStrategy},
			{K: "has_attack_path", V: f.AttackPath != nil},
			{K: "has_drift", V: f.Drift != nil},
		})
	}

	paths := make([]any, 0, len(result.AttackPaths))
	for _, p := range result.AttackPaths {
		paths = append(paths, obj{
			{K: "id", V: p.ID},
			{K: "title", V: p.Title},
			{K: "entry_point", V: p.EntryPoint},
			{K: "target", V: p.Target},
			{K: "combined_severity", V: string(p.CombinedSeverity)},
			{K: "steps_count", V: len(p.Steps)},
			{K: "findings_involved", V: p.FindingsInvolved},
		})
	}

	summary := obj{
		{K: "repository", V: result.Repository},
		{K: "commit_sha", V: result.CommitSHA},
		{K: "timestamp", V: result.Timestamp.ISOFormat()},
		{K: "depth_profile", V: result.DepthProfile},
		{K: "tier", V: result.Tier},
		{K: "providers_detected", V: result.ProvidersDetected},
		{K: "summary", V: obj{
			{K: "total_resources_scanned", V: result.TotalResourcesScanned},
			{K: "total_findings", V: len(result.Findings)},
			{K: "confirmed", V: result.Confirmed},
			{K: "likely", V: result.Likely},
			{K: "inconclusive", V: result.Inconclusive},
			{K: "not_exploitable", V: result.NotExploitable},
			{K: "noise_reduction_pct", V: result.NoiseReductionPct},
			// Python parity: by_severity is seeded `{s.value: 0 for s in
			// Severity}` and json.dumps keeps that insertion order —
			// critical, high, medium, low, info, not the alphabetical
			// critical, high, info, low, medium a Go map would produce.
			{K: "by_severity", V: orderedCounts(result.BySeverity, schemas.BySeverityOrder())},
		}},
		{K: "findings", V: findings},
		{K: "attack_paths", V: paths},
		{K: "drift", V: obj{
			{K: "drifted_resources", V: result.DriftResources},
			{K: "shadow_it_resources", V: result.ShadowITResources},
		}},
		{K: "compliance_frameworks_checked", V: result.ComplianceFrameworksChecked},
		{K: "performance", V: obj{
			{K: "duration_seconds", V: result.DurationSeconds},
			{K: "cost_usd", V: result.CostUSD},
			// Same rule as by_severity: cost_breakdown is seeded from
			// _PHASE_ORDER and json.dumps keeps that order.
			{K: "cost_breakdown", V: orderedCosts(result.CostBreakdown, schemas.CostBreakdownOrder)},
			{K: "agent_invocations", V: result.AgentInvocations},
		}},
	}
	return pyfmt.Dumps(summary, 2)
}

// RenderJSON ports render_json: the parsed form of the pretty full JSON, for an
// API response.
//
// Python parity gap: Python returns a dict, which preserves the model's field
// order all the way out through FastAPI's encoder. A Go map cannot, so a caller
// that re-serialises this value gets sorted keys. Use GenerateJSON when the
// bytes matter; use this only where the consumer looks values up by key.
//
// The error is impossible in practice (GenerateJSON always emits a valid
// document); it is returned rather than swallowed so a future change to the
// serializer cannot fail silently.
func RenderJSON(result schemas.CloudSecurityScanResult) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal([]byte(GenerateJSON(result, true)), &out); err != nil {
		return nil, fmt.Errorf("output: render_json: %w", err)
	}
	return out, nil
}

// orderedCounts / orderedCosts render a dict-typed result field with Python's
// insertion order restored: the known keys first, then any key outside that set
// in code-point order (a tail the live path cannot produce).
func orderedCounts(m map[string]int, order []string) pyfmt.Ordered {
	out := make(pyfmt.Ordered, 0, len(m))
	seen := make(map[string]bool, len(order))
	for _, k := range order {
		seen[k] = true
		if v, present := m[k]; present {
			out = append(out, pyfmt.KV{K: k, V: v})
		}
	}
	for _, k := range restKeys(len(m), seen, func(yield func(string)) {
		for k := range m {
			yield(k)
		}
	}) {
		out = append(out, pyfmt.KV{K: k, V: m[k]})
	}
	return out
}

func orderedCosts(m map[string]float64, order []string) pyfmt.Ordered {
	out := make(pyfmt.Ordered, 0, len(m))
	seen := make(map[string]bool, len(order))
	for _, k := range order {
		seen[k] = true
		if v, present := m[k]; present {
			out = append(out, pyfmt.KV{K: k, V: v})
		}
	}
	for _, k := range restKeys(len(m), seen, func(yield func(string)) {
		for k := range m {
			yield(k)
		}
	}) {
		out = append(out, pyfmt.KV{K: k, V: m[k]})
	}
	return out
}

// restKeys collects the keys not covered by `seen`, sorted.
func restKeys(size int, seen map[string]bool, each func(func(string))) []string {
	rest := make([]string, 0, size)
	each(func(k string) {
		if !seen[k] {
			rest = append(rest, k)
		}
	})
	sort.Strings(rest)
	return rest
}
