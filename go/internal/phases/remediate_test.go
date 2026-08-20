package phases

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// remediationSuggestionReply is the payload the probe's fake fix generator
// returned.
func remediationSuggestionReply() map[string]any {
	return map[string]any{
		"finding_id":             "v1",
		"description":            "fix it",
		"diffs":                  []any{},
		"breaking_change":        false,
		"effort":                 "trivial",
		"alternative_approaches": []any{},
	}
}

// TestRemediationPhase_ProbeParity reproduces the probe run: two findings, one
// CONFIRMED (gets a fix) and one NOT_EXPLOITABLE (skipped).
//
//	REM_CALLS [('cloudsecurity.run_fix_generator', ['finding', 'repo_path'])]
//	REM_REMEDIATION [True, False]
func TestRemediationPhase_ProbeParity(t *testing.T) {
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
		return remediationSuggestionReply(), nil
	}}

	in := []map[string]any{
		jsonMap(t, verifiedFinding("v1", schemas.VerdictConfirmed, scoring.SeverityHigh)),
		jsonMap(t, verifiedFinding("v2", schemas.VerdictNotExploitable, scoring.SeverityHigh)),
	}
	out, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", in, 3)
	if err != nil {
		t.Fatalf("RemediationPhase: %v", err)
	}

	if got := fake.CallTargets(); !equalStrings(got, []string{testNodeID + ".run_fix_generator"}) {
		t.Fatalf("targets = %v", got)
	}
	if got := keysOf(fake.Calls[0].Input); !equalStrings(got, []string{"finding", "repo_path"}) {
		t.Fatalf("kwargs = %v", got)
	}
	if fake.Calls[0].Input["repo_path"] != "/repo" {
		t.Fatalf("repo_path = %v", fake.Calls[0].Input["repo_path"])
	}

	verified := verifiedList(t, out)
	if len(verified) != 2 {
		t.Fatalf("verified = %d", len(verified))
	}
	if _, present := verified[0]["remediation"]; !present {
		t.Errorf("confirmed finding should have gained a remediation: %#v", verified[0])
	}
	if _, present := verified[1]["remediation"]; present {
		t.Errorf("not_exploitable finding must be left alone: %#v", verified[1])
	}
	// Order is preserved: the fix is written back at the finding's own index.
	if verified[0]["id"] != "v1" || verified[1]["id"] != "v2" {
		t.Fatalf("order changed: %v, %v", verified[0]["id"], verified[1]["id"])
	}
}

// TestRemediationPhase_SelectsConfirmedAndLikelyWithoutRemediation pins the
// `f.verdict in {CONFIRMED, LIKELY} and f.remediation is None` filter.
func TestRemediationPhase_SelectsConfirmedAndLikelyWithoutRemediation(t *testing.T) {
	withFix := verifiedFinding("has-fix", schemas.VerdictConfirmed, scoring.SeverityHigh)
	suggestion := schemas.NewRemediationSuggestion()
	suggestion.FindingID = "has-fix"
	suggestion.Description = "already fixed"
	withFix.Remediation = &suggestion

	in := []map[string]any{
		jsonMap(t, verifiedFinding("confirmed", schemas.VerdictConfirmed, scoring.SeverityHigh)),
		jsonMap(t, verifiedFinding("likely", schemas.VerdictLikely, scoring.SeverityHigh)),
		jsonMap(t, verifiedFinding("inconclusive", schemas.VerdictInconclusive, scoring.SeverityHigh)),
		jsonMap(t, verifiedFinding("not-exploitable", schemas.VerdictNotExploitable, scoring.SeverityHigh)),
		jsonMap(t, withFix),
	}

	// The generators run concurrently, so the recording map needs its own lock.
	var mu sync.Mutex
	seen := map[string]bool{}
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, kwargs map[string]any) (map[string]any, error) {
		finding := jsonMap(t, kwargs["finding"])
		mu.Lock()
		seen[finding["id"].(string)] = true
		mu.Unlock()
		return remediationSuggestionReply(), nil
	}}
	if _, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", in, 3); err != nil {
		t.Fatalf("RemediationPhase: %v", err)
	}
	if len(seen) != 2 || !seen["confirmed"] || !seen["likely"] {
		t.Fatalf("remediated %v, want confirmed + likely only", seen)
	}
}

// TestRemediationPhase_NoCandidatesShortCircuits: zero calls, and the reply
// still carries every finding in exclude_none form.
func TestRemediationPhase_NoCandidatesShortCircuits(t *testing.T) {
	fake := &appx.Fake{}
	in := []map[string]any{
		jsonMap(t, verifiedFinding("a", schemas.VerdictInconclusive, scoring.SeverityLow)),
		jsonMap(t, verifiedFinding("b", schemas.VerdictNotExploitable, scoring.SeverityLow)),
	}
	out, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", in, 3)
	if err != nil {
		t.Fatalf("RemediationPhase: %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("calls = %v", fake.CallTargets())
	}
	verified := verifiedList(t, out)
	if len(verified) != 2 {
		t.Fatalf("verified = %d", len(verified))
	}
	for _, v := range verified {
		for _, key := range []string{"attack_path", "drift", "remediation"} {
			if _, present := v[key]; present {
				t.Errorf("exclude_none should have dropped %q: %#v", key, v)
			}
		}
	}
}

// TestRemediationPhase_EmptyInput covers verified_findings=[].
func TestRemediationPhase_EmptyInput(t *testing.T) {
	fake := &appx.Fake{}
	out, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", nil, 3)
	if err != nil {
		t.Fatalf("RemediationPhase: %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("calls = %v", fake.CallTargets())
	}
	if got := verifiedList(t, out); len(got) != 0 {
		t.Fatalf("verified = %v", got)
	}
}

// TestRemediationPhase_FailuresAreSwallowed: a failing generator, a
// non-dict payload and a payload that will not bind all leave remediation unset
// and produce no error and no note.
func TestRemediationPhase_FailuresAreSwallowed(t *testing.T) {
	cases := []struct {
		name  string
		reply map[string]any
		err   error
	}{
		{name: "transport error", err: errors.New("generator down")},
		{name: "strict unwrap failure", reply: map[string]any{"error_message": "no repo"}},
		{name: "non dict payload", reply: map[string]any{"output": []any{1, 2}}},
		{name: "unbindable payload", reply: map[string]any{"diffs": "not a list"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
				return tc.reply, tc.err
			}}
			in := []map[string]any{jsonMap(t, verifiedFinding("v1", schemas.VerdictConfirmed, scoring.SeverityHigh))}
			out, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", in, 3)
			if err != nil {
				t.Fatalf("RemediationPhase must swallow failures, got %v", err)
			}
			verified := verifiedList(t, out)
			if _, present := verified[0]["remediation"]; present {
				t.Fatalf("remediation should be absent: %#v", verified[0])
			}
			if len(fake.Notes) != 0 {
				t.Fatalf("no notes expected, got %v", fake.NoteMessages())
			}
		})
	}
}

// TestRemediationPhase_SemaphoreBoundsConcurrency asserts
// max(1, min(max_concurrent_remediations, len(needs_remediation))).
func TestRemediationPhase_SemaphoreBoundsConcurrency(t *testing.T) {
	cases := []struct {
		name       string
		candidates int
		limit      int
		wantPeak   int
	}{
		{name: "limit below candidates", candidates: 6, limit: 2, wantPeak: 2},
		{name: "default limit", candidates: 6, limit: 3, wantPeak: 3},
		{name: "limit above candidates", candidates: 2, limit: 9, wantPeak: 2},
		{name: "zero limit clamps to one", candidates: 3, limit: 0, wantPeak: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := make([]map[string]any, 0, tc.candidates)
			for i := 0; i < tc.candidates; i++ {
				in = append(in, jsonMap(t, verifiedFinding(fmt.Sprintf("v%d", i), schemas.VerdictConfirmed, scoring.SeverityHigh)))
			}
			fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
				time.Sleep(25 * time.Millisecond)
				return remediationSuggestionReply(), nil
			}}
			if _, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", in, tc.limit); err != nil {
				t.Fatalf("RemediationPhase: %v", err)
			}
			if peak := fake.MaxConcurrentCalls(); peak != tc.wantPeak {
				t.Fatalf("peak concurrency = %d, want %d", peak, tc.wantPeak)
			}
		})
	}
}
