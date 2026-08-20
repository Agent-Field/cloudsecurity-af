package schemas

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Timestamp wraps time.Time to reproduce how a pydantic `datetime` field crosses
// the AgentField JSON boundary.
//
// The Python node returns `result.model_dump()` from its reasoner; model_dump()
// leaves a datetime as a datetime, and FastAPI's jsonable_encoder then calls
// `datetime.isoformat()`. Verified against the venv interpreter:
//
//	datetime(2026,1,2,3,4,5,123456,tzinfo=UTC) -> "2026-01-02T03:04:05.123456+00:00"
//	datetime(2026,1,2,3,4,5,        tzinfo=UTC) -> "2026-01-02T03:04:05+00:00"
//
// i.e. a numeric UTC offset (never "Z", which is what pydantic's OWN
// model_dump_json emits — that path is not the one the node takes), and the
// fractional part present with exactly 6 digits or omitted entirely when the
// microsecond field is zero.
//
// The only producer in this repo is orchestrator.py `datetime.now(UTC)`
// (CloudSecurityScanResult.timestamp), so the emitted offset is always "+00:00";
// MarshalJSON nonetheless honors whatever zone the wrapped time carries, as
// isoformat() does.
type Timestamp struct {
	time.Time
}

// pyISOLayoutNoFraction / pyISOLayoutFraction are Go layouts for
// datetime.isoformat(). "-07:00" (rather than "Z07:00") forces the numeric
// offset form even for UTC, matching Python.
const (
	pyISOLayoutNoFraction = "2006-01-02T15:04:05-07:00"
	pyISOLayoutFraction   = "2006-01-02T15:04:05.000000-07:00"
)

// NewTimestamp wraps t, truncated to microsecond resolution — Python's datetime
// has no sub-microsecond precision, so a Go time.Time carrying nanoseconds would
// otherwise round-trip differently.
func NewTimestamp(t time.Time) Timestamp {
	return Timestamp{Time: t.Truncate(time.Microsecond)}
}

// NowUTC ports `datetime.now(UTC)` — the only Timestamp producer in the node.
func NowUTC() Timestamp {
	return NewTimestamp(time.Now().UTC())
}

// ISOFormat renders the value exactly as Python's datetime.isoformat() does.
// output/report.py and output/sarif.py interpolate `result.timestamp.isoformat()`
// into their text, so this must stay byte-identical for those ports too.
func (ts Timestamp) ISOFormat() string {
	t := ts.Truncate(time.Microsecond)
	if t.Nanosecond() == 0 {
		return t.Format(pyISOLayoutNoFraction)
	}
	return t.Format(pyISOLayoutFraction)
}

// MarshalJSON emits the ISOFormat string.
func (ts Timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(ts.ISOFormat())
}

// timestampParseLayouts covers both representations a Timestamp can arrive in:
// Python's isoformat (numeric offset, optional 6-digit fraction) and RFC 3339
// with a "Z" designator — which is what pydantic's model_dump_json() produces,
// and what a Go or non-Python peer would send. Naive (offset-less) forms are
// accepted last and interpreted as UTC.
var timestampParseLayouts = []string{
	time.RFC3339Nano,                // 2026-01-02T03:04:05.123456+00:00 and ...Z
	time.RFC3339,                    // 2026-01-02T03:04:05+00:00 and ...Z
	"2006-01-02T15:04:05.999999999", // naive with fraction (datetime.now() with no tz)
	"2006-01-02T15:04:05",           // naive without fraction
}

// UnmarshalJSON accepts either representation (see timestampParseLayouts) and a
// JSON null, which yields the zero Timestamp.
func (ts *Timestamp) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*ts = Timestamp{}
		return nil
	}
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("schemas: Timestamp must be a string: %w", err)
	}
	raw = strings.TrimSpace(raw)
	for _, layout := range timestampParseLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			*ts = NewTimestamp(t)
			return nil
		}
	}
	return fmt.Errorf("schemas: %q is not a datetime.isoformat() or RFC 3339 timestamp", raw)
}
