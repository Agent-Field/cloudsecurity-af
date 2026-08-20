package schemas

import (
	"encoding/json"
	"testing"
	"time"
)

// This file pins schemas.Timestamp against the two representations design §2
// requires it to handle, with the expected strings verified against
// ~/.agentfield/packages/cloudsecurity-af/venv/bin/python:
//
//	jsonable_encoder(CloudSecurityScanResult(...).model_dump())["timestamp"]
//	  datetime(2026,1,2,3,4,5,123456, tz=UTC) -> "2026-01-02T03:04:05.123456+00:00"
//	  datetime(2026,1,2,3,4,5,        tz=UTC) -> "2026-01-02T03:04:05+00:00"
//	CloudSecurityScanResult(...).model_dump_json()
//	  -> "2026-01-02T03:04:05.123456Z"   (the OTHER representation, accepted on input)

func TestTimestamp_MarshalMatchesPythonIsoformat(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want string
	}{
		{
			"microseconds present",
			time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC),
			`"2026-01-02T03:04:05.123456+00:00"`,
		},
		{
			// Python omits the fractional part entirely when microsecond == 0.
			"microseconds zero",
			time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			`"2026-01-02T03:04:05+00:00"`,
		},
		{
			// isoformat() always pads to 6 digits when the fraction is present.
			"trailing zeros padded to six digits",
			time.Date(2026, 1, 2, 3, 4, 5, 120000000, time.UTC),
			`"2026-01-02T03:04:05.120000+00:00"`,
		},
		{
			// Sub-microsecond precision does not exist in Python's datetime;
			// NewTimestamp truncates so a Go time.Time round-trips identically.
			"nanoseconds truncated to microseconds",
			time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC),
			`"2026-01-02T03:04:05.123456+00:00"`,
		},
		{
			// isoformat() renders whatever offset the datetime carries; the node
			// only ever produces UTC, but a non-UTC zone must not become "Z".
			"non-utc offset rendered numerically",
			time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("", -7*3600)),
			`"2026-01-02T03:04:05-07:00"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := json.Marshal(NewTimestamp(c.in))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestTimestamp_ISOFormatMatchesMarshal(t *testing.T) {
	// output/report.py and output/sarif.py interpolate
	// `result.timestamp.isoformat()` directly into their text, so ISOFormat()
	// must produce the same string MarshalJSON quotes.
	ts := NewTimestamp(time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC))
	if got := ts.ISOFormat(); got != "2026-01-02T03:04:05.123456+00:00" {
		t.Errorf("ISOFormat() = %q", got)
	}
	raw, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `"`+ts.ISOFormat()+`"` {
		t.Errorf("MarshalJSON %s does not wrap ISOFormat %q", raw, ts.ISOFormat())
	}
}

func TestTimestamp_UnmarshalAcceptsBothRepresentations(t *testing.T) {
	want := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	cases := []struct {
		name string
		in   string
		want time.Time
	}{
		{"python isoformat with offset", `"2026-01-02T03:04:05.123456+00:00"`, want},
		{"rfc3339 with Z", `"2026-01-02T03:04:05.123456Z"`, want},
		{"no fraction with offset", `"2026-01-02T03:04:05+00:00"`, want.Truncate(time.Second)},
		{"no fraction with Z", `"2026-01-02T03:04:05Z"`, want.Truncate(time.Second)},
		{"naive with fraction", `"2026-01-02T03:04:05.123456"`, want},
		{"naive without fraction", `"2026-01-02T03:04:05"`, want.Truncate(time.Second)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ts Timestamp
			if err := json.Unmarshal([]byte(c.in), &ts); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !ts.Equal(c.want) {
				t.Errorf("got %v, want %v", ts.Time, c.want)
			}
		})
	}
}

func TestTimestamp_UnmarshalRejectsGarbageAndAcceptsNull(t *testing.T) {
	var ts Timestamp
	if err := json.Unmarshal([]byte(`"not a timestamp"`), &ts); err == nil {
		t.Error("want an error for an unparseable timestamp")
	}
	if err := json.Unmarshal([]byte(`12345`), &ts); err == nil {
		t.Error("want an error for a non-string timestamp")
	}
	ts = NewTimestamp(time.Now())
	if err := json.Unmarshal([]byte(`null`), &ts); err != nil {
		t.Fatalf("null should decode to the zero Timestamp: %v", err)
	}
	if !ts.IsZero() {
		t.Errorf("null decoded to %v, want the zero time", ts.Time)
	}
}

func TestTimestamp_RoundTripThroughScanResult(t *testing.T) {
	// The end-to-end shape the control plane sees.
	r := NewCloudSecurityScanResult()
	r.Repository = "/tmp/repo"
	r.CommitSHA = "abc123"
	r.DepthProfile = "standard"
	r.Tier = 1
	r.Timestamp = NewTimestamp(time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC))

	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded CloudSecurityScanResult
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !decoded.Timestamp.Equal(r.Timestamp.Time) {
		t.Errorf("round trip changed the timestamp: %v -> %v", r.Timestamp.Time, decoded.Timestamp.Time)
	}
	if got := mustJSONMap(t, r)["timestamp"]; got != "2026-01-02T03:04:05.123456+00:00" {
		t.Errorf("timestamp key = %v", got)
	}
}

func TestNowUTC(t *testing.T) {
	ts := NowUTC()
	if ts.Location() != time.UTC {
		t.Errorf("NowUTC location = %v, want UTC", ts.Location())
	}
	if ts.Nanosecond()%1000 != 0 {
		t.Errorf("NowUTC must be truncated to microsecond resolution, got %d ns", ts.Nanosecond())
	}
	if d := time.Since(ts.Time); d < -time.Second || d > time.Minute {
		t.Errorf("NowUTC is %v away from now", d)
	}
}
