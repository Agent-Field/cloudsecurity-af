package pyfmt

import (
	"math"
	"strconv"
	"testing"
)

// Every expectation in this file was captured from the repo's own interpreter:
//
//	~/.agentfield/packages/cloudsecurity-af/venv/bin/python -c '<one-liner>'
//
// (CPython 3.11.12). The one-liner that produced each block is quoted above it,
// so the table can be regenerated and re-diffed at any time.

// ---------------------------------------------------------------------------
// Round
// ---------------------------------------------------------------------------

// Captured with:
//
//	python -c "print([round(2.675,2), round(0.125,2), round(0.375,2), round(1.5,0), round(2.5,0), round(33.3333333,2)])"
//	-> [2.67, 0.12, 0.38, 2.0, 2.0, 33.33]
//	python -c "print([round(-2.675,2), round(2.5,1), round(1.005,2), round(0.5,0), round(1.25,1), round(1.35,1)])"
//	-> [-2.67, 2.5, 1.0, 0.0, 1.2, 1.4]
//	python -c "print([round(1234.5678,-2), round(1250.0,-2), round(1350.0,-2), round(123456789.987654321,4), round(1e16,2), round(2.675,10)])"
//	-> [1200.0, 1200.0, 1400.0, 123456789.9877, 1e+16, 2.675]
func TestRound_PythonGroundTruth(t *testing.T) {
	cases := []struct {
		name    string
		x       float64
		ndigits int
		want    float64
	}{
		// The canonical "why a naive x*100+0.5 is wrong" trio.
		{"2.675 is really 2.67499999999999982", 2.675, 2, 2.67},
		{"0.125 is an exact tie -> even", 0.125, 2, 0.12},
		{"0.375 is an exact tie -> even (up)", 0.375, 2, 0.38},
		{"round(1.5) ties to even", 1.5, 0, 2},
		{"round(2.5) ties to even (down)", 2.5, 0, 2},
		{"plain truncation case", 33.3333333, 2, 33.33},

		{"negative mirrors positive", -2.675, 2, -2.67},
		{"already at ndigits", 2.5, 1, 2.5},
		{"1.005 is really 1.00499999999999989", 1.005, 2, 1.0},
		{"round(0.5) ties down to zero", 0.5, 0, 0},
		{"1.25 ties to even (down)", 1.25, 1, 1.2},
		{"1.35 is really 1.350000000000000088", 1.35, 1, 1.4},

		{"negative ndigits", 1234.5678, -2, 1200},
		{"negative ndigits tie to even (down)", 1250.0, -2, 1200},
		{"negative ndigits tie to even (up)", 1350.0, -2, 1400},
		{"many digits", 123456789.987654321, 4, 123456789.9877},
		{"huge magnitude is unchanged", 1e16, 2, 1e16},
		{"ndigits past the precision is a no-op", 2.675, 10, 2.675},

		{"zero", 0.0, 2, 0.0},
		{"guard: ndigits above NDIGITS_MAX", 1.23456, 400, 1.23456},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Round(tc.x, tc.ndigits)
			if got != tc.want {
				t.Fatalf("Round(%v, %d) = %v, want %v", tc.x, tc.ndigits, got, tc.want)
			}
		})
	}
}

// Captured with:
//
//	python -c "import math; print(repr(round(-0.5,0)), repr(round(-0.0,2)), math.copysign(1, round(-0.5,0)))"
//	-> -0.0 -0.0 -1.0
//
// The sign of a zero result follows the input, because CPython round-trips
// through a decimal string that carries the "-".
func TestRound_PreservesNegativeZero(t *testing.T) {
	for _, tc := range []struct {
		x       float64
		ndigits int
	}{{-0.5, 0}, {math.Copysign(0, -1), 2}, {-0.0001, 2}} {
		got := Round(tc.x, tc.ndigits)
		if got != 0 {
			t.Fatalf("Round(%v, %d) = %v, want a zero", tc.x, tc.ndigits, got)
		}
		if !math.Signbit(got) {
			t.Fatalf("Round(%v, %d) lost the negative zero", tc.x, tc.ndigits)
		}
	}
}

// Captured with:
//
//	python -c "print(round(float('inf'),2), round(float('-inf'),2), round(float('nan'),2))"
//	-> inf -inf nan
func TestRound_NonFiniteIsReturnedUnchanged(t *testing.T) {
	if got := Round(math.Inf(1), 2); !math.IsInf(got, 1) {
		t.Fatalf("Round(+Inf, 2) = %v", got)
	}
	if got := Round(math.Inf(-1), 2); !math.IsInf(got, -1) {
		t.Fatalf("Round(-Inf, 2) = %v", got)
	}
	if got := Round(math.NaN(), 2); !math.IsNaN(got) {
		t.Fatalf("Round(NaN, 2) = %v", got)
	}
}

// ---------------------------------------------------------------------------
// FormatFloat
// ---------------------------------------------------------------------------

// Captured with:
//
//	python -c "print([str(f) for f in [0.0,1.0,100.0,0.1,1/3,1e15,1e16,1e17,1.5e16,0.0001,0.00001,1e-7,123456789.0,1234567.0,1e300,5e-324,2.675,3.14159,-2.5,1e21,9007199254740992.0,1.2345678901234567e19]])"
//	-> ['0.0', '1.0', '100.0', '0.1', '0.3333333333333333', '1000000000000000.0',
//	    '1e+16', '1e+17', '1.5e+16', '0.0001', '1e-05', '1e-07', '123456789.0',
//	    '1234567.0', '1e+300', '5e-324', '2.675', '3.14159', '-2.5', '1e+21',
//	    '9007199254740992.0', '1.2345678901234567e+19']
func TestFormatFloat_PythonGroundTruth(t *testing.T) {
	cases := []struct {
		f    float64
		want string
	}{
		{0.0, "0.0"},
		{1.0, "1.0"},
		{100.0, "100.0"},
		{0.1, "0.1"},
		{1.0 / 3.0, "0.3333333333333333"},
		// The 1e16 fixed/scientific cutoff CPython hard-codes.
		{1e15, "1000000000000000.0"},
		{1e16, "1e+16"},
		{1e17, "1e+17"},
		{1.5e16, "1.5e+16"},
		// The -4 cutoff on the small side.
		{0.0001, "0.0001"},
		{0.00001, "1e-05"},
		{1e-7, "1e-07"},
		// Go's %g would render these two as 1.23456789e+08 / 1.234567e+06.
		{123456789.0, "123456789.0"},
		{1234567.0, "1234567.0"},
		{1e300, "1e+300"},
		{5e-324, "5e-324"},
		{2.675, "2.675"},
		{3.14159, "3.14159"},
		{-2.5, "-2.5"},
		{1e21, "1e+21"},
		{9007199254740992.0, "9007199254740992.0"},
		{1.2345678901234567e19, "1.2345678901234567e+19"},
	}
	for _, tc := range cases {
		if got := FormatFloat(tc.f); got != tc.want {
			t.Errorf("FormatFloat(%v) = %q, want %q", tc.f, got, tc.want)
		}
	}
}

// Captured with:
//
//	python -c "print(str(-0.0), str(float('inf')), str(float('-inf')), str(float('nan')))"
//	-> -0.0 inf -inf nan
func TestFormatFloat_SpecialValues(t *testing.T) {
	cases := []struct {
		f    float64
		want string
	}{
		{math.Copysign(0, -1), "-0.0"},
		{math.Inf(1), "inf"},
		{math.Inf(-1), "-inf"},
		{math.NaN(), "nan"},
	}
	for _, tc := range cases {
		if got := FormatFloat(tc.f); got != tc.want {
			t.Errorf("FormatFloat(%v) = %q, want %q", tc.f, got, tc.want)
		}
	}
}

// FormatFloat must be the inverse of Go's parser for every float it renders —
// that is the definition of "shortest round-tripping repr".
func TestFormatFloat_RoundTrips(t *testing.T) {
	for _, f := range []float64{0.1, 1.0 / 3.0, 2.675, 1e16, 5e-324, 1e300, -1234.5678, 9007199254740993.0} {
		s := FormatFloat(f)
		back, err := strconv.ParseFloat(s, 64)
		if err != nil {
			t.Fatalf("re-parsing %q: %v", s, err)
		}
		if back != f {
			t.Errorf("FormatFloat(%v) = %q did not round-trip (got %v)", f, s, back)
		}
	}
}
