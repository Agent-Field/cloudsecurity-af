package node

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/orch"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// VALIDATION CONTRACT — the `scan` / `prove` reply BYTES.
//
// app.py:216 returns `result.model_dump()` and FastAPI serialises it with
// json.dumps, which preserves the dict's insertion order — pydantic's FIELD
// DECLARATION order. Ground truth, read off the live model under the repo venv:
//
//	list(CloudSecurityScanResult.model_fields)
//	  -> repository, commit_sha, branch, timestamp, depth_profile, tier,
//	     providers_detected, findings, attack_paths, total_resources_scanned,
//	     total_raw_findings, confirmed, likely, inconclusive, not_exploitable,
//	     noise_reduction_pct, by_severity, drift_resources, shadow_it_resources,
//	     compliance_frameworks_checked, compliance_gaps, strategies_used,
//	     duration_seconds, agent_invocations, cost_usd, cost_breakdown,
//	     metadata, sarif
//
// and the body it produces starts
//
//	{"repository": "/repo", "commit_sha": "c", "branch": null, ...
//
// Returning a Go map instead put the same keys on the wire alphabetically
// (agent_invocations, attack_paths, branch, by_severity, commit_sha, …) and
// rendered `"cost_usd": 0.0` as `0`.
var pythonScanResultFieldOrder = []string{
	"repository", "commit_sha", "branch", "timestamp", "depth_profile", "tier",
	"providers_detected", "findings", "attack_paths", "total_resources_scanned",
	"total_raw_findings", "confirmed", "likely", "inconclusive", "not_exploitable",
	"noise_reduction_pct", "by_severity", "drift_resources", "shadow_it_resources",
	"compliance_frameworks_checked", "compliance_gaps", "strategies_used",
	"duration_seconds", "agent_invocations", "cost_usd", "cost_breakdown",
	"metadata", "sarif",
}

func TestRunPipeline_ReplyKeepsPydanticFieldOrder(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		result := schemas.NewCloudSecurityScanResult()
		result.Repository = "/repo"
		result.CommitSHA = "c"
		return result, nil
	}

	out, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
	if err != nil {
		t.Fatalf("runPipeline: %v", err)
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}

	got := topLevelKeys(t, body)
	if len(got) != len(pythonScanResultFieldOrder) {
		t.Fatalf("keys = %v\nwant %v", got, pythonScanResultFieldOrder)
	}
	for i, want := range pythonScanResultFieldOrder {
		if got[i] != want {
			t.Fatalf("key %d = %q, want %q\ngot  %v\nwant %v", i, got[i], want, got, pythonScanResultFieldOrder)
		}
	}

	// The float fields keep Python's spelling. encoding/json compacts a
	// Marshaler's bytes, dropping the ", " / ": " separators — the same
	// separators FastAPI's JSONResponse uses.
	for _, want := range []string{`"noise_reduction_pct":0.0`, `"cost_usd":0.0`, `"duration_seconds":0.0`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("reply does not contain %s\n%s", want, body)
		}
	}
}

// topLevelKeys returns a JSON object's keys in document order.
func topLevelKeys(t *testing.T, body []byte) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(body)))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("body is not a JSON object: %s", body)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("scan key: %v", err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatalf("expected a key, got %v", tok)
		}
		keys = append(keys, key)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			t.Fatalf("decode value of %q: %v", key, err)
		}
	}
	return keys
}

// VALIDATION CONTRACT — the reply's two SEEDED DICTS keep Python's insertion
// order, not the alphabetical order a Go map renders with.
//
// orchestrator.py seeds both from a fixed sequence and never adds a key:
//
//	severity_counts = {s.value: 0 for s in Severity}                 (:165)
//	_PHASE_ORDER = ("recon", "hunt", "chain", "prove", "remediate")  (:54)
//	self.cost_breakdown = {phase: 0.0 for phase in self._PHASE_ORDER} (:67)
//
// Ground truth from the repo venv — CloudSecurityScanResult(...).model_dump()
// with critical=1 and a freshly seeded cost_breakdown, rendered with
// json.dumps:
//
//	{"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
//	{"recon": 0.0, "hunt": 0.0, "chain": 0.0, "prove": 0.0, "remediate": 0.0}
//
// Sorting them instead puts "info" second and "chain" first, and spells every
// cost as `0` rather than `0.0`.
func TestRunPipeline_ReplySeededDictsKeepPythonInsertionOrder(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		result := schemas.NewCloudSecurityScanResult()
		result.Repository = "/repo"
		result.BySeverity = map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
		result.CostBreakdown = map[string]float64{}
		for _, phase := range schemas.CostBreakdownOrder {
			result.CostBreakdown[phase] = 0.0
		}
		return result, nil
	}

	out, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
	if err != nil {
		t.Fatalf("runPipeline: %v", err)
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}

	// encoding/json compacts the Marshaler's bytes, so the wire spelling drops
	// json.dumps' ", " / ": " separators — as FastAPI's JSONResponse does.
	for _, want := range []string{
		`"by_severity":{"critical":1,"high":0,"medium":0,"low":0,"info":0}`,
		`"cost_breakdown":{"recon":0.0,"hunt":0.0,"chain":0.0,"prove":0.0,"remediate":0.0}`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("reply does not contain %s\ngot %s", want, body)
		}
	}
}

// A key the seeded order does not name still appears — sorted, after the known
// ones — rather than being dropped. Python cannot reach this state
// (_register_cost only mutates existing entries), so the tail is purely
// defensive; what it must never do is lose data.
func TestRunPipeline_UnknownSeededDictKeyIsKeptAtTheEnd(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		result := schemas.NewCloudSecurityScanResult()
		result.CostBreakdown = map[string]float64{"remediate": 1.0, "recon": 2.0, "zzz": 3.0, "aaa": 4.0}
		return result, nil
	}

	out, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
	if err != nil {
		t.Fatalf("runPipeline: %v", err)
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	const want = `"cost_breakdown":{"recon":2.0,"remediate":1.0,"aaa":4.0,"zzz":3.0}`
	if !strings.Contains(string(body), want) {
		t.Errorf("reply does not contain %s\ngot %s", want, body)
	}
}
