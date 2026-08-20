package scoring

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// This file ports tests/test_scoring.py 1:1. Every Go test names the Python
// class::test it mirrors so reviewers can diff coverage, plus a handful of extra
// tests that pin behavior the Python suite only exercises implicitly (the
// exhaustive score matrix, the rounding mode, and the enum helpers).

// approx mirrors pytest.approx(expected, abs=tol).
func approx(t *testing.T, label string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s: got %v, want %v (+/- %v)", label, got, want, tol)
	}
}

// --- TestComputeRiskScore (tests/test_scoring.py::TestComputeRiskScore) -----

// test_critical_live_internet
func TestComputeRiskScore_CriticalLiveInternet(t *testing.T) {
	score := ComputeRiskScore(SeverityCritical, EvidenceMethodLiveVerified, ExposureInternetFacing, false, false)
	if score != 10.0 {
		t.Fatalf("got %v, want 10.0", score)
	}
}

// test_info_heuristic_admin — pytest.approx(0.04, abs=0.01); Python's exact
// value is 0.04, so this asserts equality as well as the tolerance.
func TestComputeRiskScore_InfoHeuristicAdmin(t *testing.T) {
	score := ComputeRiskScore(SeverityInfo, EvidenceMethodHeuristicMatch, ExposureRequiresAdmin, false, false)
	approx(t, "info/heuristic/admin", score, 0.04, 0.01)
	if score != 0.04 {
		t.Fatalf("exact parity: got %v, want 0.04", score)
	}
}

// test_attack_path_bonus
func TestComputeRiskScore_AttackPathBonus(t *testing.T) {
	base := ComputeRiskScore(SeverityHigh, EvidenceMethodStaticConfigMatch, ExposureVPCInternal, false, false)
	withPath := ComputeRiskScore(SeverityHigh, EvidenceMethodStaticConfigMatch, ExposureVPCInternal, true, false)
	approx(t, "attack path bonus", withPath, base*2.0, 0.01)
	// Exact Python values, checked against the interpreter.
	if base != 2.8 || withPath != 5.6 {
		t.Fatalf("exact parity: base=%v withPath=%v, want 2.8 / 5.6", base, withPath)
	}
}

// test_drift_bonus
func TestComputeRiskScore_DriftBonus(t *testing.T) {
	base := ComputeRiskScore(SeverityMedium, EvidenceMethodDriftConfirmed, ExposurePrivateSubnet, false, false)
	withDrift := ComputeRiskScore(SeverityMedium, EvidenceMethodDriftConfirmed, ExposurePrivateSubnet, false, true)
	approx(t, "drift bonus", withDrift, base*1.3, 0.01)
	// Exact Python values: 5*0.85*0.5 = 2.125 -> round-half-EVEN -> 2.12
	// (math.Round would give 2.13), and 2.7625 -> 2.76.
	if base != 2.12 || withDrift != 2.76 {
		t.Fatalf("exact parity: base=%v withDrift=%v, want 2.12 / 2.76", base, withDrift)
	}
}

// test_score_clamped_at_10
func TestComputeRiskScore_ClampedAt10(t *testing.T) {
	score := ComputeRiskScore(SeverityCritical, EvidenceMethodLiveVerified, ExposureInternetFacing, true, true)
	if score != 10.0 {
		t.Fatalf("got %v, want 10.0", score)
	}
}

// test_score_non_negative
func TestComputeRiskScore_NonNegative(t *testing.T) {
	score := ComputeRiskScore(SeverityInfo, EvidenceMethodHeuristicMatch, ExposureRequiresAdmin, false, false)
	if score < 0.0 {
		t.Fatalf("got %v, want >= 0", score)
	}
}

// TestComputeRiskScore_PythonMatrix replays every (severity x evidence x
// exposure x path x drift) combination captured from the Python implementation
// by scripts/gen_scoring_matrix.py and requires bit-identical float64s. This is
// the test that would catch a rounding-mode regression anywhere in the table.
func TestComputeRiskScore_PythonMatrix(t *testing.T) {
	type row struct {
		Severity       string  `json:"severity"`
		EvidenceMethod string  `json:"evidence_method"`
		Exposure       string  `json:"exposure"`
		HasAttackPath  bool    `json:"has_attack_path"`
		HasDrift       bool    `json:"has_drift"`
		Score          float64 `json:"score"`
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "risk_score_matrix.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var rows []row
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	want := len(AllSeverities) * len(AllEvidenceMethods) * len(AllExposures) * 2 * 2
	if len(rows) != want {
		t.Fatalf("fixture has %d rows, want %d — regenerate with scripts/gen_scoring_matrix.py", len(rows), want)
	}
	for _, r := range rows {
		sev, err := ParseSeverity(r.Severity)
		if err != nil {
			t.Fatalf("fixture severity %q: %v", r.Severity, err)
		}
		ev, err := ParseEvidenceMethod(r.EvidenceMethod)
		if err != nil {
			t.Fatalf("fixture evidence %q: %v", r.EvidenceMethod, err)
		}
		exp, err := ParseExposure(r.Exposure)
		if err != nil {
			t.Fatalf("fixture exposure %q: %v", r.Exposure, err)
		}
		got := ComputeRiskScore(sev, ev, exp, r.HasAttackPath, r.HasDrift)
		if got != r.Score {
			t.Errorf("ComputeRiskScore(%s, %s, %s, path=%v, drift=%v) = %v, want %v",
				r.Severity, r.EvidenceMethod, r.Exposure, r.HasAttackPath, r.HasDrift, got, r.Score)
		}
	}
}

// --- TestBenchmarkSeverityFloor (tests/test_scoring.py::TestBenchmarkSeverityFloor)

func strptr(s string) *string { return &s }

// test_floor_upgrades_severity
func TestBenchmarkSeverityFloor_FloorUpgradesSeverity(t *testing.T) {
	if got := ApplyBenchmarkSeverityFloor(strptr("CIS-AWS-1.4"), SeverityLow); got != SeverityCritical {
		t.Fatalf("got %q, want %q", got, SeverityCritical)
	}
}

// test_floor_no_downgrade
func TestBenchmarkSeverityFloor_NoDowngrade(t *testing.T) {
	if got := ApplyBenchmarkSeverityFloor(strptr("CIS-AWS-2.1.1"), SeverityCritical); got != SeverityCritical {
		t.Fatalf("got %q, want %q", got, SeverityCritical)
	}
}

// test_unknown_benchmark_passthrough
func TestBenchmarkSeverityFloor_UnknownBenchmarkPassthrough(t *testing.T) {
	if got := ApplyBenchmarkSeverityFloor(strptr("CIS-AWS-99.99"), SeverityLow); got != SeverityLow {
		t.Fatalf("got %q, want %q", got, SeverityLow)
	}
}

// test_none_benchmark_passthrough — Python passes None; Go passes a nil *string.
func TestBenchmarkSeverityFloor_NoneBenchmarkPassthrough(t *testing.T) {
	if got := ApplyBenchmarkSeverityFloor(nil, SeverityMedium); got != SeverityMedium {
		t.Fatalf("got %q, want %q", got, SeverityMedium)
	}
}

// TestBenchmarkSeverityFloor_Table walks every entry in the floor table with a
// severity below, equal to, and above the floor. Not in the Python suite; it
// pins the full table (8 controls) against accidental edits.
func TestBenchmarkSeverityFloor_Table(t *testing.T) {
	wantFloors := map[string]Severity{
		"CIS-AWS-1.4":   SeverityCritical,
		"CIS-AWS-1.5":   SeverityCritical,
		"CIS-AWS-2.1.1": SeverityHigh,
		"CIS-AWS-2.1.2": SeverityHigh,
		"CIS-AWS-2.2.1": SeverityHigh,
		"CIS-AWS-3.1":   SeverityHigh,
		"CIS-AWS-4.1":   SeverityHigh,
		"CIS-AWS-5.1":   SeverityHigh,
	}
	if len(benchmarkSeverityFloors) != len(wantFloors) {
		t.Fatalf("floor table has %d entries, want %d", len(benchmarkSeverityFloors), len(wantFloors))
	}
	for id, floor := range wantFloors {
		// Below the floor -> upgraded to the floor.
		if got := ApplyBenchmarkSeverityFloor(strptr(id), SeverityInfo); got != floor {
			t.Errorf("%s from info: got %q, want %q", id, got, floor)
		}
		// At the floor -> unchanged.
		if got := ApplyBenchmarkSeverityFloor(strptr(id), floor); got != floor {
			t.Errorf("%s at floor: got %q, want %q", id, got, floor)
		}
		// Above the floor -> never downgraded.
		if got := ApplyBenchmarkSeverityFloor(strptr(id), SeverityCritical); got != SeverityCritical {
			t.Errorf("%s from critical: got %q, want %q", id, got, SeverityCritical)
		}
	}
}

// --- TestSeverityLabelFromScore (tests/test_scoring.py::TestSeverityLabelFromScore)

// test_label_mapping (all 10 parametrize cases)
func TestSeverityLabelFromScore_LabelMapping(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{10.0, "critical"},
		{9.0, "critical"},
		{8.5, "high"},
		{7.0, "high"},
		{5.0, "medium"},
		{4.0, "medium"},
		{2.0, "low"},
		{1.0, "low"},
		{0.5, "info"},
		{0.0, "info"},
	}
	for _, c := range cases {
		if got := SeverityLabelFromScore(c.score); got != c.want {
			t.Errorf("SeverityLabelFromScore(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

// --- Extra coverage not present in tests/test_scoring.py ---------------------

// TestRounding pins the parity trap at the seam scoring actually uses:
// Python round() is round-half-to-even on the true binary value, while Go's
// math.Round is half-away-from-zero. The implementation lives in
// internal/pyfmt (which has its own, broader suite); this asserts the values
// scoring itself depends on, captured from the venv interpreter.
func TestRounding(t *testing.T) {
	cases := []struct {
		in     float64
		digits int
		want   float64
	}{
		{0.125, 2, 0.12},  // ties-to-even rounds DOWN (math.Round -> 0.13)
		{0.0625, 2, 0.06}, // ties-to-even rounds DOWN
		{2.675, 2, 2.67},  // binary repr is just below the tie
		{1.005, 2, 1.0},   // binary repr is just below the tie
		{2.125, 2, 2.12},  // the drift-bonus case from TestComputeRiskScore
		{2.7625, 2, 2.76}, // 2.125 * 1.3
		{0.04, 2, 0.04},   // exact
		{10.0, 2, 10.0},   // exact
		{0.135, 2, 0.14},  // ties-to-even rounds UP here
	}
	for _, c := range cases {
		if got := pyfmt.Round(c.in, c.digits); got != c.want {
			t.Errorf("pyfmt.Round(%v, %d) = %v, want %v", c.in, c.digits, got, c.want)
		}
	}
}

// TestSeverityEnum pins the member values and the strict Parse/Valid helpers.
func TestSeverityEnum(t *testing.T) {
	want := []string{"critical", "high", "medium", "low", "info"}
	if len(AllSeverities) != len(want) {
		t.Fatalf("AllSeverities has %d members, want %d", len(AllSeverities), len(want))
	}
	for i, w := range want {
		if AllSeverities[i].String() != w {
			t.Errorf("AllSeverities[%d] = %q, want %q", i, AllSeverities[i], w)
		}
		if !AllSeverities[i].Valid() {
			t.Errorf("%q should be Valid", AllSeverities[i])
		}
	}
	if Severity("bogus").Valid() {
		t.Error(`Severity("bogus") should not be Valid`)
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("ParseSeverity(bogus) should error, matching pydantic ValidationError")
	}
	if _, err := ParseSeverity("CRITICAL"); err == nil {
		t.Error("ParseSeverity is case-sensitive like Python's Enum(value)")
	}
}

// TestEvidenceAndExposureEnums pins the remaining two vocabularies.
func TestEvidenceAndExposureEnums(t *testing.T) {
	wantEvidence := []string{
		"live_verified", "iam_simulated", "drift_confirmed",
		"static_graph_confirmed", "static_config_match", "heuristic_match",
	}
	for i, w := range wantEvidence {
		if AllEvidenceMethods[i].String() != w {
			t.Errorf("AllEvidenceMethods[%d] = %q, want %q", i, AllEvidenceMethods[i], w)
		}
	}
	if len(AllEvidenceMethods) != len(wantEvidence) {
		t.Errorf("AllEvidenceMethods has %d members, want %d", len(AllEvidenceMethods), len(wantEvidence))
	}
	wantExposure := []string{
		"internet_facing", "vpc_internal", "private_subnet",
		"requires_iam_auth", "requires_admin",
	}
	for i, w := range wantExposure {
		if AllExposures[i].String() != w {
			t.Errorf("AllExposures[%d] = %q, want %q", i, AllExposures[i], w)
		}
	}
	if len(AllExposures) != len(wantExposure) {
		t.Errorf("AllExposures has %d members, want %d", len(AllExposures), len(wantExposure))
	}
	if _, err := ParseEvidenceMethod("nope"); err == nil {
		t.Error("ParseEvidenceMethod(nope) should error")
	}
	if _, err := ParseExposure("nope"); err == nil {
		t.Error("ParseExposure(nope) should error")
	}
}

// TestEnumJSONRoundTrip checks that the enums marshal to their Python value and
// that UnmarshalJSON is strict (pydantic raises for an unknown member or null).
func TestEnumJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(SeverityHigh)
	if err != nil || string(b) != `"high"` {
		t.Fatalf("marshal Severity: %s, %v", b, err)
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"low"`), &s); err != nil || s != SeverityLow {
		t.Fatalf("unmarshal Severity: %q, %v", s, err)
	}
	if err := json.Unmarshal([]byte(`"bogus"`), &s); err == nil {
		t.Error("unmarshal of an unknown Severity should error (pydantic parity)")
	}
	if err := json.Unmarshal([]byte(`null`), &s); err == nil {
		t.Error("unmarshal of null into Severity should error (pydantic parity)")
	}
	var m EvidenceMethod
	if err := json.Unmarshal([]byte(`"drift_confirmed"`), &m); err != nil || m != EvidenceMethodDriftConfirmed {
		t.Fatalf("unmarshal EvidenceMethod: %q, %v", m, err)
	}
	var e Exposure
	if err := json.Unmarshal([]byte(`"vpc_internal"`), &e); err != nil || e != ExposureVPCInternal {
		t.Fatalf("unmarshal Exposure: %q, %v", e, err)
	}
}

// TestMultiplierTables pins the three weight/multiplier tables byte-exact
// against scoring.py.
func TestMultiplierTables(t *testing.T) {
	wantSeverity := map[string]float64{"critical": 10.0, "high": 8.0, "medium": 5.0, "low": 3.0, "info": 1.0}
	if len(SeverityWeights) != len(wantSeverity) {
		t.Fatalf("SeverityWeights has %d entries, want %d", len(SeverityWeights), len(wantSeverity))
	}
	for k, v := range wantSeverity {
		if SeverityWeights[k] != v {
			t.Errorf("SeverityWeights[%q] = %v, want %v", k, SeverityWeights[k], v)
		}
	}
	wantEvidence := map[EvidenceMethod]float64{
		EvidenceMethodLiveVerified:         1.0,
		EvidenceMethodIAMSimulated:         0.9,
		EvidenceMethodDriftConfirmed:       0.85,
		EvidenceMethodStaticGraphConfirmed: 0.7,
		EvidenceMethodStaticConfigMatch:    0.5,
		EvidenceMethodHeuristicMatch:       0.2,
	}
	if len(EvidenceMultipliers) != len(wantEvidence) {
		t.Fatalf("EvidenceMultipliers has %d entries, want %d", len(EvidenceMultipliers), len(wantEvidence))
	}
	for k, v := range wantEvidence {
		if EvidenceMultipliers[k] != v {
			t.Errorf("EvidenceMultipliers[%q] = %v, want %v", k, EvidenceMultipliers[k], v)
		}
	}
	wantExposure := map[Exposure]float64{
		ExposureInternetFacing:  1.0,
		ExposureVPCInternal:     0.7,
		ExposurePrivateSubnet:   0.5,
		ExposureRequiresIAMAuth: 0.4,
		ExposureRequiresAdmin:   0.2,
	}
	if len(ExposureMultipliers) != len(wantExposure) {
		t.Fatalf("ExposureMultipliers has %d entries, want %d", len(ExposureMultipliers), len(wantExposure))
	}
	for k, v := range wantExposure {
		if ExposureMultipliers[k] != v {
			t.Errorf("ExposureMultipliers[%q] = %v, want %v", k, ExposureMultipliers[k], v)
		}
	}
}
