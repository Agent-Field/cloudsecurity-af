package phases

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// VALIDATION CONTRACT — the reasoner reply BYTES.
//
// A Python reasoner returns `result.model_dump()` (or a dict literal) and
// FastAPI serialises it with json.dumps, which preserves a dict's insertion
// order. So the reply's key order is pydantic's FIELD-DECLARATION order, and
// every float field is spelled the Python way. Both were read off the live
// models under the repo venv:
//
//	list(ReconResult.model_fields)  -> inventory, resource_graph, drift_report,
//	    live_inventory, iac_type, providers_detected, total_resources,
//	    total_edges, recon_duration_seconds
//	list(HuntResult.model_fields)   -> findings, total_raw, deduplicated_count,
//	    strategies_run, hunt_duration_seconds
//	list(ChainResult.model_fields)  -> attack_paths, total_paths_evaluated,
//	    viable_paths, chain_duration_seconds
//	reasoners/phases.py:317-322     -> verified, total_selected, total_findings,
//	                                   not_verified   (a dict LITERAL)
//	reasoners/phases.py:367         -> verified
//	json.dumps(VerifiedFinding(...).model_dump(exclude_none=True))
//	                                -> ..."risk_score": 0.0, ...,
//	                                   "sarif_security_severity": 0.0, ...
//
// A Go map return produced sorted keys (deduplicated_count, findings,
// hunt_duration_seconds, strategies_run, total_raw) and `0` for every integral
// float. afx.Payload restores both.

// jsonKeys returns the top-level keys of a JSON object in DOCUMENT order.
func jsonKeys(t *testing.T, body []byte) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(body)))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("body is not a JSON object: %s", body)
	}
	var keys []string
	depth := 0
	for dec.More() || depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("scan %s: %v", body, err)
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth < 0 {
					return keys
				}
			}
		case string:
			if depth == 0 {
				keys = append(keys, v)
				// Skip this key's value wholesale.
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					t.Fatalf("decode value of %q: %v", v, err)
				}
			}
		}
	}
	return keys
}

func TestPhaseReplies_KeepPydanticFieldOrderOnTheWire(t *testing.T) {
	t.Run("recon_phase", func(t *testing.T) {
		fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
			if strings.HasSuffix(target, ".run_iac_reader") {
				return map[string]any{"inventory_saved_path": "/tmp/inv.json"}, nil
			}
			return map[string]any{"graph_saved_path": "/tmp/graph.json"}, nil
		}}
		out, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", "standard", 1, nil)
		if err != nil {
			t.Fatalf("ReconPhase: %v", err)
		}
		assertKeyOrder(t, out, []string{
			"inventory", "resource_graph", "drift_report", "live_inventory", "iac_type",
			"providers_detected", "total_resources", "total_edges", "recon_duration_seconds",
		})
	})

	t.Run("prove_phase", func(t *testing.T) {
		hunt := huntResultMap(t)
		out, err := ProvePhase(context.Background(), &appx.Fake{}, testNodeID, "/repo", hunt, chainResultMap(t), "standard", 1, 3)
		if err != nil {
			t.Fatalf("ProvePhase: %v", err)
		}
		// phases.py:317-322 returns the LITERAL dict in this order.
		assertKeyOrder(t, out, []string{"verified", "total_selected", "total_findings", "not_verified"})
	})

	t.Run("remediation_phase", func(t *testing.T) {
		out, err := RemediationPhase(context.Background(), &appx.Fake{}, testNodeID, "/repo", nil, 3)
		if err != nil {
			t.Fatalf("RemediationPhase: %v", err)
		}
		assertKeyOrder(t, out, []string{"verified"})
	})
}

// assertKeyOrder marshals the reply exactly as the SDK does and compares the
// document's key order.
func assertKeyOrder(t *testing.T, reply any, want []string) {
	t.Helper()
	body, err := json.Marshal(reply)
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	got := jsonKeys(t, body)
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d = %q, want %q (full order %v, want %v)", i, got[i], want[i], got, want)
		}
	}
}

// Python renders a pydantic float field as `0.0`; encoding/json renders
// float64(0) as `0`. The reply bytes are what an external consumer parses, so
// the spelling is observable.
func TestPhaseReplies_SpellFloatsThePythonWay(t *testing.T) {
	hunt := huntResultMap(t, rawFinding("p1", scoring.SeverityHigh, "fp1", "c"))
	fake := &appx.Fake{CallFn: func(context.Context, string, map[string]any) (map[string]any, error) {
		// A prover reply with no risk_score: the model default 0.0 applies.
		return map[string]any{
			"title": "t", "verdict": string(schemas.VerdictConfirmed),
			"severity": string(scoring.SeverityHigh), "category": "c",
		}, nil
	}}
	out, err := ProvePhase(context.Background(), fake, testNodeID, "/repo", hunt, chainResultMap(t), "standard", 1, 3)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// encoding/json COMPACTS a Marshaler's output, dropping the ", " / ": "
	// separators — which is also what FastAPI's JSONResponse does
	// (json.dumps(..., separators=(",", ":"))), so the wire bytes agree.
	for _, want := range []string{`"risk_score":0.0`, `"sarif_security_severity":0.0`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("reply does not contain %s\n%s", want, body)
		}
	}
	// hunt_duration_seconds is the same story on the hunt reply.
	huntOut, err := HuntPhase(context.Background(), &appx.Fake{}, testNodeID, "/repo", "/g", "/i", "standard", 3)
	if err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}
	huntBody, err := json.Marshal(huntOut)
	if err != nil {
		t.Fatalf("marshal hunt: %v", err)
	}
	if !strings.Contains(string(huntBody), `"hunt_duration_seconds":0.0`) {
		t.Errorf("hunt reply does not spell hunt_duration_seconds as 0.0\n%s", huntBody)
	}
}

// The `verified` ENTRIES are model_dump(exclude_none=True) dicts, and Python
// keeps their field order too. Ground truth from the repo venv:
//
//	json.dumps(VerifiedFinding(title="t", verdict="confirmed", severity="high",
//	                           category="c").model_dump(exclude_none=True))
//	-> id, title, verdict, severity, category, resources, proof,
//	   compliance_mappings, risk_score, sarif_rule_id, sarif_security_severity,
//	   iac_file, iac_line, config_snippet, description, fingerprint,
//	   hunter_strategy
//
// (attack_path, drift, remediation and drop_reason are dropped by exclude_none.)
func TestProvePhase_VerifiedEntriesKeepPydanticFieldOrder(t *testing.T) {
	hunt := huntResultMap(t, rawFinding("p1", scoring.SeverityHigh, "fp1", "c"))
	fake := &appx.Fake{CallFn: func(context.Context, string, map[string]any) (map[string]any, error) {
		return map[string]any{
			"title": "t", "verdict": string(schemas.VerdictConfirmed),
			"severity": string(scoring.SeverityHigh), "category": "c",
		}, nil
	}}
	out, err := ProvePhase(context.Background(), fake, testNodeID, "/repo", hunt, chainResultMap(t), "standard", 1, 3)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Pull the first object out of the "verified" array and read its key order.
	var envelope struct {
		Verified []json.RawMessage `json:"verified"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode envelope: %v\n%s", err, body)
	}
	if len(envelope.Verified) != 1 {
		t.Fatalf("verified = %d entries, want 1", len(envelope.Verified))
	}
	got := jsonKeys(t, envelope.Verified[0])
	want := []string{
		"id", "title", "verdict", "severity", "category", "resources", "proof",
		"compliance_mappings", "risk_score", "sarif_rule_id", "sarif_security_severity",
		"iac_file", "iac_line", "config_snippet", "description", "fingerprint",
		"hunter_strategy",
	}
	if len(got) != len(want) {
		t.Fatalf("verified entry keys = %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("verified entry key %d = %q, want %q\ngot  %v\nwant %v", i, got[i], want[i], got, want)
		}
	}
}
