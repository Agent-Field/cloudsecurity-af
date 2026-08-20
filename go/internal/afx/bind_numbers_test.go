package afx

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// VALIDATION CONTRACT — integers inside `Any`-typed model fields.
//
// The drift detector's report crosses the control plane (run_drift_detector ->
// recon_phase -> ReconResult -> orchestrator -> chain_phase / prove_phase) and
// is re-materialised with `DriftReport.model_validate(...)`. Its
// `iac_config` / `live_config` are `dict[str, Any]`
// (src/cloudsecurity_af/schemas/recon.py:119-120) and ConfigDiff's
// `iac_value` / `live_value` are `Any`, so an IaC port, retention period, TTL
// or capacity unit lands there as an INTEGER.
//
// Ground truth — the repo venv on the same wire payload:
//
//	DriftReport.model_validate(wire).model_dump() -> json.dumps(indent=2)
//	  "iac_config": {"port": 5432, "backup_retention_period": 7,
//	                 "multi_az": false, "ratio": 0.5}
//	  "diffs": [{"attribute": "port", "iac_value": 5432, "live_value": 3306,
//	             "security_impact": null}]
//
// Those exact bytes reach the LLM through {{DRIFT_REPORT_JSON}} in the CHAIN
// parent prompt and through {{FINDING_JSON}} in the fix-generator prompt, and
// they land in .cloudsecurity/checkpoint-recon.json and the scan result. A
// float64 decode renders every one of them as `5432.0` / `7.0`.
const driftWireJSON = `{
  "drifted_resources": [{
    "resource_id": "aws_db_instance.main",
    "resource_type": "aws_db_instance",
    "iac_config": {"port": 5432, "backup_retention_period": 7, "multi_az": false, "ratio": 0.5},
    "live_config": {"port": 3306},
    "diffs": [{"attribute": "port", "iac_value": 5432, "live_value": 3306, "security_impact": null}],
    "security_relevant": true,
    "significance": "high"
  }],
  "iac_only_resources": [],
  "cloud_only_resources": []
}`

func TestBind_KeepsIntegersInsideAnyTypedFields(t *testing.T) {
	var wire map[string]any
	if err := json.Unmarshal([]byte(driftWireJSON), &wire); err != nil {
		t.Fatalf("decode wire: %v", err)
	}

	report, err := Bind[schemas.DriftReport](wire)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	rendered := pyfmt.Dumps(report, 2)

	for _, want := range []string{
		`"port": 5432`,
		`"backup_retention_period": 7`,
		`"ratio": 0.5`,
		`"iac_value": 5432`,
		`"live_value": 3306`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered drift report is missing %s\n%s", want, rendered)
		}
	}
	for _, unwanted := range []string{"5432.0", "3306.0", `"backup_retention_period": 7.0`} {
		if strings.Contains(rendered, unwanted) {
			t.Errorf("rendered drift report contains %s; Python renders the integer\n%s", unwanted, rendered)
		}
	}
}

// The same guarantee has to survive the custom default-seeding UnmarshalJSON,
// which decodes the raw bytes a second time: json.Unmarshal there would undo
// Bind's UseNumber for every model that has one (DriftedResource and DriftReport
// both do).
func TestUnmarshalJSON_KeepsIntegersInsideAnyTypedFields(t *testing.T) {
	var report schemas.DriftReport
	if err := json.Unmarshal([]byte(driftWireJSON), &report); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := report.DriftedResources[0].IaCConfig["port"]
	n, ok := got.(json.Number)
	if !ok || n.String() != "5432" {
		t.Fatalf("iac_config[port] = %#v, want json.Number(\"5432\")", got)
	}
	if diff := report.DriftedResources[0].Diffs[0].IaCValue; diff != json.Number("5432") {
		t.Fatalf("diffs[0].iac_value = %#v, want json.Number(\"5432\")", diff)
	}
}

// Typed fields must be unaffected by UseNumber.
func TestBind_TypedNumericFieldsAreStillDecodedByType(t *testing.T) {
	in, err := Bind[schemas.ResourceInventory](map[string]any{
		"inventory_saved_path": "/tmp/inventory.json",
		"total_resources":      float64(3),
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if in.TotalResources != 3 {
		t.Fatalf("TotalResources = %d, want 3", in.TotalResources)
	}
}

// The OTHER half of the UseNumber trade-off: an integral float inside an `Any`
// leaf loses Python's float spelling, and cannot be recovered here.
//
// The Go SDK decodes the reasoner body with a plain encoding/json decoder (no
// UseNumber anywhere in sdk/go), so a wire `7.0` is already float64(7) before
// Bind runs; Bind's own re-marshal writes `7` and UseNumber pins that literal.
//
// Ground truth — the repo venv on the identical wire bytes
// `{"resource_id":"r","resource_type":"t","iac_config":{"ratio":7.0,"n":5}}`:
//
//	DriftedResource.model_validate(json.loads(wire)).model_dump()
//	  -> "iac_config": {"ratio": 7.0, "n": 5}
//
// This test pins the port's actual output so the divergence is visible and a
// future change to the SDK's decoder (or to Bind) shows up here rather than as
// a silent prompt-byte drift.
func TestBind_IntegralFloatInAnyLeafLosesTheFloatSpelling(t *testing.T) {
	// What the SDK hands the handler: every number already a float64.
	var input map[string]any
	if err := json.Unmarshal([]byte(`{"resource_id":"r","resource_type":"t","iac_config":{"ratio":7.0,"n":5}}`), &input); err != nil {
		t.Fatalf("decode wire: %v", err)
	}
	if _, ok := input["iac_config"].(map[string]any)["ratio"].(float64); !ok {
		t.Fatalf("premise broken: the SDK decoder no longer collapses numbers to float64")
	}

	bound, err := Bind[schemas.DriftedResource](input)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got := pyfmt.DumpsCompact(bound.IaCConfig)
	// DIVERGENCE: Python prints {"ratio": 7.0, "n": 5}. The int stays an int
	// (the half UseNumber buys); the integral float is indistinguishable from
	// it by the time Bind runs. The key order is pyfmt.Dumps' documented
	// map-sorting deviation.
	if want := `{"n": 5, "ratio": 7}`; got != want {
		t.Errorf("iac_config = %s, want %s", got, want)
	}
	// The integer half must keep working: 5 must never become 5.0.
	if strings.Contains(got, "5.0") {
		t.Errorf("an integer literal was re-rendered as a float: %s", got)
	}
}
