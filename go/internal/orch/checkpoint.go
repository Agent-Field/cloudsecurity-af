package orch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// checkpointDirPerm / checkpointFilePerm mirror the CPython defaults:
// Path.mkdir() defaults to mode=0o777 and open(..., "w") to 0o666, both then
// masked by the process umask — which is what Go's os.MkdirAll / os.WriteFile
// perm arguments do too.
const (
	checkpointDirPerm  os.FileMode = 0o777
	checkpointFilePerm os.FileMode = 0o666
)

// CheckpointPath is `self.checkpoint_dir / f"checkpoint-{phase}.json"`.
func (o *ScanOrchestrator) CheckpointPath(phase string) string {
	return filepath.Join(o.CheckpointDir, "checkpoint-"+phase+".json")
}

// WriteCheckpoint ports _write_checkpoint for a single pydantic model.
//
// Python:
//
//	self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
//	path = self.checkpoint_dir / f"checkpoint-{phase}.json"
//	data = payload.model_dump()
//	body = {"phase": phase, "created_at": datetime.now(UTC).isoformat(), "data": data}
//	path.write_text(json.dumps(body, indent=2), encoding="utf-8")
//
// The body's key order (phase, created_at, data) is observable in the file, so
// it is built as a pyfmt.Ordered rather than a Go map, and rendered with
// pyfmt.Dumps — CPython's json.dumps spelling, not encoding/json's (float
// repr, ensure_ascii, no <>& escaping, ", "/": " separators).
func (o *ScanOrchestrator) WriteCheckpoint(phase string, payload any) error {
	return o.writeCheckpointBody(phase, payload)
}

// WriteCheckpointList ports the `isinstance(payload, list)` branch of
// _write_checkpoint: `data = [item.model_dump() for item in payload]`. The only
// caller is the "prove" checkpoint, which stores []VerifiedFinding.
func (o *ScanOrchestrator) WriteCheckpointList(phase string, payload []schemas.VerifiedFinding) error {
	return o.writeCheckpointBody(phase, payload)
}

func (o *ScanOrchestrator) writeCheckpointBody(phase string, data any) error {
	if err := os.MkdirAll(o.CheckpointDir, checkpointDirPerm); err != nil {
		return fmt.Errorf("orch: create checkpoint dir: %w", err)
	}
	body := pyfmt.Ordered{
		{K: "phase", V: phase},
		{K: "created_at", V: o.nowUTC().ISOFormat()},
		{K: "data", V: data},
	}
	path := o.CheckpointPath(phase)
	if err := os.WriteFile(path, []byte(pyfmt.Dumps(body, 2)), checkpointFilePerm); err != nil {
		return fmt.Errorf("orch: write checkpoint %s: %w", path, err)
	}
	return nil
}

// ReadCheckpoint ports _read_checkpoint:
//
//	payload = json.loads(path.read_text(encoding="utf-8"))
//	return schema(**payload.get("data", {}))
//
// Nothing in cloudsecurity-af calls it — there is no resume-from-checkpoint
// path, unlike sec-af — but it is part of the class and is ported so the
// checkpoint format has a reader that a future resume path (and this package's
// tests) can use.
//
// Python parity: a checkpoint whose top level is not an object, or whose "data"
// is not an object, raises; so does this, via the JSON decode.
func ReadCheckpoint[T any](o *ScanOrchestrator, phase string) (T, error) {
	var zero T
	raw, err := os.ReadFile(o.CheckpointPath(phase))
	if err != nil {
		return zero, fmt.Errorf("orch: read checkpoint: %w", err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return zero, fmt.Errorf("orch: decode checkpoint: %w", err)
	}
	data, present := body["data"]
	if !present {
		// Python parity: payload.get("data", {}) -> schema(**{}).
		return afx.Bind[T](map[string]any{})
	}
	var asMap map[string]any
	if err := json.Unmarshal(data, &asMap); err != nil {
		return zero, fmt.Errorf("orch: decode checkpoint data: %w", err)
	}
	return afx.Bind[T](asMap)
}
