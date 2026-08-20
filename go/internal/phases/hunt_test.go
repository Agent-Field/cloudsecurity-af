package phases

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// huntReply builds the HuntResult dump a hunter returns.
func huntReply(t *testing.T, findings ...schemas.RawFinding) map[string]any {
	t.Helper()
	h := schemas.NewHuntResult()
	h.Findings = findings
	h.TotalRaw = len(findings)
	h.DeduplicatedCount = len(findings)
	h.StrategiesRun = []string{}
	return mustMap(t, h)
}

// hunterNameOf turns "cloudsecurity.run_iam_hunter" into "iam".
func hunterNameOf(target string) string {
	name := strings.TrimPrefix(target, testNodeID+".run_")
	return strings.TrimSuffix(name, "_hunter")
}

// TestHuntPhase_DepthSelectsHunters pins DEPTH_HUNTER_MAP's fan-out. The Python
// probe recorded, for depth="quick":
//
//	['cloudsecurity.run_iam_hunter', 'cloudsecurity.run_network_hunter',
//	 'cloudsecurity.run_data_hunter', 'cloudsecurity.run_secrets_hunter',
//	 'cloudsecurity.run_compute_hunter']
func TestHuntPhase_DepthSelectsHunters(t *testing.T) {
	cases := []struct {
		depth string
		want  []string
	}{
		{depth: "quick", want: []string{"iam", "network", "data", "secrets", "compute"}},
		{depth: "standard", want: []string{"iam", "network", "data", "secrets", "compute", "logging", "compliance"}},
		{depth: "thorough", want: []string{"iam", "network", "data", "secrets", "compute", "logging", "compliance"}},
		// _normalize_depth lowercases, then falls back to STANDARD.
		{depth: "QUICK", want: []string{"iam", "network", "data", "secrets", "compute"}},
		{depth: "bogus", want: []string{"iam", "network", "data", "secrets", "compute", "logging", "compliance"}},
		{depth: "", want: []string{"iam", "network", "data", "secrets", "compute", "logging", "compliance"}},
	}
	for _, tc := range cases {
		t.Run(tc.depth, func(t *testing.T) {
			fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
				return huntReply(t), nil
			}}
			out, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", "/g.json", "/i.json", tc.depth, 3)
			if err != nil {
				t.Fatalf("HuntPhase: %v", err)
			}

			got := make([]string, 0, len(fake.Calls))
			for _, c := range fake.CallTargets() {
				got = append(got, hunterNameOf(c))
			}
			sortStrings(got)
			wantSorted := append([]string(nil), tc.want...)
			sortStrings(wantSorted)
			if !equalStrings(got, wantSorted) {
				t.Fatalf("hunters called = %v, want %v", got, wantSorted)
			}
			// strategies_run keeps DEPTH_HUNTER_MAP's declaration order.
			strategies, ok := pm(out)["strategies_run"].([]string)
			if !ok {
				t.Fatalf("strategies_run is %T", pm(out)["strategies_run"])
			}
			if !equalStrings(strategies, tc.want) {
				t.Fatalf("strategies_run = %v, want %v", strategies, tc.want)
			}
		})
	}
}

// TestHuntPhase_HunterKwargs pins the four kwargs every hunter receives; the
// Python probe recorded ['depth', 'inventory_path', 'repo_path',
// 'resource_graph_path'].
func TestHuntPhase_HunterKwargs(t *testing.T) {
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
		return huntReply(t), nil
	}}
	if _, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", "/g.json", "/i.json", "quick", 3); err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}
	for _, c := range fake.Calls {
		if got := keysOf(c.Input); !equalStrings(got, []string{"depth", "inventory_path", "repo_path", "resource_graph_path"}) {
			t.Fatalf("%s kwargs = %v", c.Target, got)
		}
		if c.Input["repo_path"] != "/repo" || c.Input["resource_graph_path"] != "/g.json" ||
			c.Input["inventory_path"] != "/i.json" || c.Input["depth"] != "quick" {
			t.Fatalf("%s kwargs values = %v", c.Target, c.Input)
		}
	}
}

// TestHuntPhase_FailedHunterContributesEmptyBatchAndNoNote reproduces the probe
// run where run_secrets_hunter raised: 5 hunters called, 4 findings, total_raw 4,
// strategies_run still lists all five, and NOT ONE note is emitted.
func TestHuntPhase_FailedHunterContributesEmptyBatchAndNoNote(t *testing.T) {
	fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
		name := hunterNameOf(target)
		if name == "secrets" {
			return map[string]any{"error_message": "nope"}, nil
		}
		return huntReply(t, rawFinding("run_"+name+"_hunter", scoring.SeverityMedium, "fp-run_"+name+"_hunter", name)), nil
	}}

	out, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", "/g.json", "/i.json", "quick", 3)
	if err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}
	if len(fake.Calls) != 5 {
		t.Fatalf("call count = %d", len(fake.Calls))
	}
	if pm(out)["total_raw"] != 4 {
		t.Errorf("total_raw = %v, want 4", pm(out)["total_raw"])
	}
	if pm(out)["deduplicated_count"] != 4 {
		t.Errorf("deduplicated_count = %v, want 4", pm(out)["deduplicated_count"])
	}
	if pm(out)["hunt_duration_seconds"] != 0.0 {
		t.Errorf("hunt_duration_seconds = %v, want 0.0", pm(out)["hunt_duration_seconds"])
	}
	ids := make([]string, 0, 4)
	for _, f := range pm(out)["findings"].([]schemas.RawFinding) {
		ids = append(ids, f.ID)
	}
	sortStrings(ids)
	want := []string{"run_compute_hunter", "run_data_hunter", "run_iam_hunter", "run_network_hunter"}
	if !equalStrings(ids, want) {
		t.Fatalf("finding ids = %v, want %v", ids, want)
	}
	if len(fake.Notes) != 0 {
		t.Fatalf("hunt_phase must not emit notes, got %v", fake.NoteMessages())
	}
}

// TestHuntPhase_TransportErrorAlsoYieldsEmptyBatch covers the other half of the
// bare `except Exception` — a call that fails at the transport level, not in the
// envelope.
func TestHuntPhase_TransportErrorAlsoYieldsEmptyBatch(t *testing.T) {
	fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
		if hunterNameOf(target) == "iam" {
			return nil, context.DeadlineExceeded
		}
		return huntReply(t), nil
	}}
	out, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", "/g.json", "/i.json", "quick", 3)
	if err != nil {
		t.Fatalf("HuntPhase must swallow hunter failures, got %v", err)
	}
	if pm(out)["total_raw"] != 0 {
		t.Errorf("total_raw = %v", pm(out)["total_raw"])
	}
}

// TestHuntPhase_IncrementalFingerprintDedup: total_raw counts every finding the
// hunters produced, while findings holds only the first per fingerprint.
func TestHuntPhase_IncrementalFingerprintDedup(t *testing.T) {
	fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
		name := hunterNameOf(target)
		// Every hunter reports the SAME fingerprint plus one of its own, and
		// each finding gets its own category so cross-hunter dedup is a no-op.
		return huntReply(t,
			rawFinding("shared-"+name, scoring.SeverityMedium, "shared-fp", "cat-shared-"+name),
			rawFinding("own-"+name, scoring.SeverityMedium, "fp-"+name, "cat-own-"+name),
		), nil
	}}
	out, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", "/g.json", "/i.json", "quick", 3)
	if err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}
	if pm(out)["total_raw"] != 10 {
		t.Errorf("total_raw = %v, want 10", pm(out)["total_raw"])
	}
	// 5 own + 1 shared survivor.
	if pm(out)["deduplicated_count"] != 6 {
		t.Errorf("deduplicated_count = %v, want 6", pm(out)["deduplicated_count"])
	}
}

// TestHuntPhase_SynthesizesMissingFingerprint pins
// f"{iac_file}:{iac_line}:{category}" and the fact that it is written back onto
// the finding.
func TestHuntPhase_SynthesizesMissingFingerprint(t *testing.T) {
	fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
		if hunterNameOf(target) != "iam" {
			return huntReply(t), nil
		}
		blank := rawFinding("blank", scoring.SeverityMedium, "", "public_access")
		blank.IaCFile = "infra/main.tf"
		blank.IaCLine = 42
		return huntReply(t, blank), nil
	}}
	out, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", "/g.json", "/i.json", "quick", 3)
	if err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}
	findings := pm(out)["findings"].([]schemas.RawFinding)
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	if got, want := findings[0].Fingerprint, "infra/main.tf:42:public_access"; got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
}

// TestHuntPhase_SemaphoreBoundsConcurrency asserts the
// max(1, min(max_concurrent_hunters, len(active_hunters))) bound.
func TestHuntPhase_SemaphoreBoundsConcurrency(t *testing.T) {
	cases := []struct {
		name     string
		depth    string
		limit    int
		wantPeak int
	}{
		{name: "limit below hunter count", depth: "standard", limit: 2, wantPeak: 2},
		{name: "default limit", depth: "standard", limit: 3, wantPeak: 3},
		{name: "limit above hunter count", depth: "quick", limit: 50, wantPeak: 5},
		{name: "zero limit clamps to one", depth: "quick", limit: 0, wantPeak: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
				time.Sleep(25 * time.Millisecond)
				return huntReply(t), nil
			}}
			if _, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", "/g.json", "/i.json", tc.depth, tc.limit); err != nil {
				t.Fatalf("HuntPhase: %v", err)
			}
			if peak := fake.MaxConcurrentCalls(); peak > tc.wantPeak {
				t.Fatalf("peak concurrency = %d, want <= %d", peak, tc.wantPeak)
			} else if peak < tc.wantPeak {
				t.Fatalf("peak concurrency = %d, want %d (the semaphore should be saturated)", peak, tc.wantPeak)
			}
		})
	}
}

// TestCrossHunterDedup reproduces the Python probe's three cases exactly.
func TestCrossHunterDedup(t *testing.T) {
	t.Run("highest severity wins and keeps the first position", func(t *testing.T) {
		// probe: CROSS_DEDUP ['b', 'c']
		in := []schemas.RawFinding{
			rawFinding("a", scoring.SeverityLow, "fp1", "public_access"),
			rawFinding("b", scoring.SeverityCritical, "fp2", "public_access"),
			rawFinding("c", scoring.SeverityHigh, "fp3", "other"),
		}
		got := idsOf(crossHunterDedup(in))
		if !equalStrings(got, []string{"b", "c"}) {
			t.Fatalf("ids = %v, want [b c]", got)
		}
	})

	t.Run("ties keep the first finding", func(t *testing.T) {
		// probe: CROSS_TIE ['d']
		in := []schemas.RawFinding{
			rawFinding("d", scoring.SeverityHigh, "fp4", "public_access"),
			rawFinding("e", scoring.SeverityHigh, "fp5", "public_access"),
		}
		got := idsOf(crossHunterDedup(in))
		if !equalStrings(got, []string{"d"}) {
			t.Fatalf("ids = %v, want [d]", got)
		}
	})

	t.Run("dedup key prefers resources[0].resource_id over iac_file", func(t *testing.T) {
		withResource := rawFinding("r1", scoring.SeverityLow, "fp1", "public_access")
		withResource.Resources = []schemas.AffectedResource{{ResourceID: "aws_s3_bucket.a"}}
		other := rawFinding("r2", scoring.SeverityCritical, "fp2", "public_access")
		other.Resources = []schemas.AffectedResource{{ResourceID: "aws_s3_bucket.b"}}
		same := rawFinding("r3", scoring.SeverityCritical, "fp3", "public_access")
		same.Resources = []schemas.AffectedResource{{ResourceID: "aws_s3_bucket.a"}}

		got := idsOf(crossHunterDedup([]schemas.RawFinding{withResource, other, same}))
		// r3 replaces r1 in r1's slot (higher severity, same key).
		if !equalStrings(got, []string{"r3", "r2"}) {
			t.Fatalf("ids = %v, want [r3 r2]", got)
		}
	})

	t.Run("unknown severity ranks below info", func(t *testing.T) {
		unknown := rawFinding("u", scoring.Severity("weird"), "fp1", "public_access")
		info := rawFinding("i", scoring.SeverityInfo, "fp2", "public_access")
		got := idsOf(crossHunterDedup([]schemas.RawFinding{unknown, info}))
		if !equalStrings(got, []string{"i"}) {
			t.Fatalf("ids = %v, want [i]", got)
		}
	})
}

func idsOf(findings []schemas.RawFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}
