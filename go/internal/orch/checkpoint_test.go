package orch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// wantChainCheckpoint is the literal file CPython writes for
//
//	_write_checkpoint("chain", ChainResult(attack_paths=[], total_paths_evaluated=3,
//	                                       viable_paths=1, chain_duration_seconds=1.5))
//
// with created_at pinned — captured from this repo's venv interpreter.
const wantChainCheckpoint = `{
  "phase": "chain",
  "created_at": "2026-01-02T03:04:05.123456+00:00",
  "data": {
    "attack_paths": [],
    "total_paths_evaluated": 3,
    "viable_paths": 1,
    "chain_duration_seconds": 1.5
  }
}`

// wantProveCheckpoint is the same for the list branch, one VerifiedFinding.
// Note it is a FULL model_dump: the null optional fields are present, unlike the
// exclude_none dumps the phases return.
const wantProveCheckpoint = `{
  "phase": "prove",
  "created_at": "2026-01-02T03:04:05.123456+00:00",
  "data": [
    {
      "id": "z",
      "title": "t",
      "verdict": "confirmed",
      "severity": "high",
      "category": "public_access",
      "resources": [],
      "attack_path": null,
      "drift": null,
      "proof": {
        "method": "static_analysis",
        "evidence": [],
        "scripts_executed": [],
        "verification_tier": "static"
      },
      "compliance_mappings": [],
      "risk_score": 0.0,
      "remediation": null,
      "sarif_rule_id": "r",
      "sarif_security_severity": 0.0,
      "iac_file": "main.tf",
      "iac_line": 2,
      "config_snippet": "",
      "description": "d",
      "fingerprint": "fp",
      "hunter_strategy": "iam",
      "drop_reason": null
    }
  ]
}`

// TestWriteCheckpoint_MatchesPythonBytes compares the Go checkpoint file with
// the exact bytes json.dumps(body, indent=2) produces in CPython.
func TestWriteCheckpoint_MatchesPythonBytes(t *testing.T) {
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())

	chain := schemas.NewChainResult()
	chain.TotalPathsEvaluated = 3
	chain.ViablePaths = 1
	chain.ChainDurationSeconds = 1.5
	if err := o.WriteCheckpoint("chain", chain); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
	got, err := os.ReadFile(o.CheckpointPath("chain"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != wantChainCheckpoint {
		t.Fatalf("chain checkpoint mismatch\n--- got ---\n%s\n--- want ---\n%s", got, wantChainCheckpoint)
	}

	finding := verifiedFinding("z", schemas.VerdictConfirmed, scoring.SeverityHigh)
	if err := o.WriteCheckpointList("prove", []schemas.VerifiedFinding{finding}); err != nil {
		t.Fatalf("WriteCheckpointList: %v", err)
	}
	got, err = os.ReadFile(o.CheckpointPath("prove"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != wantProveCheckpoint {
		t.Fatalf("prove checkpoint mismatch\n--- got ---\n%s\n--- want ---\n%s", got, wantProveCheckpoint)
	}
}

// TestWriteCheckpoint_CreatesTheDirectoryTree covers mkdir(parents=True).
func TestWriteCheckpoint_CreatesTheDirectoryTree(t *testing.T) {
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	o.CheckpointDir = filepath.Join(t.TempDir(), "deep", "nested", ".cloudsecurity")
	if err := o.WriteCheckpoint("recon", schemas.NewReconResult()); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
	if _, err := os.Stat(o.CheckpointPath("recon")); err != nil {
		t.Fatalf("checkpoint missing: %v", err)
	}
}

// TestCheckpointPath pins the f"checkpoint-{phase}.json" name.
func TestCheckpointPath(t *testing.T) {
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	want := filepath.Join(o.CheckpointDir, "checkpoint-hunt.json")
	if got := o.CheckpointPath("hunt"); got != want {
		t.Fatalf("CheckpointPath = %q, want %q", got, want)
	}
}

// TestReadCheckpoint_RoundTrip covers _read_checkpoint's
// `schema(**payload.get("data", {}))`.
func TestReadCheckpoint_RoundTrip(t *testing.T) {
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())

	hunt := schemas.NewHuntResult()
	hunt.Findings = []schemas.RawFinding{rawFinding("f1", scoring.SeverityCritical, "fp1")}
	hunt.TotalRaw = 9
	hunt.DeduplicatedCount = 1
	hunt.StrategiesRun = []string{"iam"}
	hunt.HuntDurationSeconds = 2.25
	if err := o.WriteCheckpoint("hunt", hunt); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}

	got, err := ReadCheckpoint[schemas.HuntResult](o, "hunt")
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if got.TotalRaw != 9 || got.DeduplicatedCount != 1 || got.HuntDurationSeconds != 2.25 {
		t.Fatalf("round trip = %#v", got)
	}
	if len(got.Findings) != 1 || got.Findings[0].ID != "f1" ||
		got.Findings[0].EstimatedSeverity != scoring.SeverityCritical {
		t.Fatalf("findings = %#v", got.Findings)
	}
	if !equalStrings(got.StrategiesRun, []string{"iam"}) {
		t.Fatalf("strategies_run = %v", got.StrategiesRun)
	}
}

// TestReadCheckpoint_MissingDataKeySeedsDefaults covers the
// `payload.get("data", {})` fallback.
func TestReadCheckpoint_MissingDataKeySeedsDefaults(t *testing.T) {
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	if err := os.MkdirAll(o.CheckpointDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := []byte(`{"phase": "chain", "created_at": "2026-01-02T03:04:05+00:00"}`)
	if err := os.WriteFile(o.CheckpointPath("chain"), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadCheckpoint[schemas.ChainResult](o, "chain")
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if got.AttackPaths == nil || len(got.AttackPaths) != 0 {
		t.Fatalf("attack_paths = %#v, want the [] default", got.AttackPaths)
	}
}

// TestReadCheckpoint_MissingFileErrors.
func TestReadCheckpoint_MissingFileErrors(t *testing.T) {
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	if _, err := ReadCheckpoint[schemas.ChainResult](o, "nope"); err == nil {
		t.Fatal("expected an error for a missing checkpoint")
	}
}
