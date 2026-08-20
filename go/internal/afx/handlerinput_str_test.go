package afx

import (
	"encoding/json"
	"testing"
)

// VALIDATION CONTRACT — `str(value)` on a JSON number.
//
// Python's reasoner endpoint runs the body through
// `Agent._validate_handler_input`, whose `str` branch is `result[name] = str(value)`.
// CPython's json.loads makes an INT out of a literal with no "." and no
// exponent, so an integer literal str()s without a fraction. Ground truth from
// the repo venv, calling the INSTALLED validator on
//
//	json.loads('{"repo_url":123,"depth":4,"branch":7.0,"severity_threshold":2.5,"cloud_provider":1e30}')
//
// with all five declared `str`:
//
//	{'repo_url': '123', 'depth': '4', 'branch': '7.0',
//	 'severity_threshold': '2.5', 'cloud_provider': '1e+30'}
//
// The Go SDK's body decoder has no UseNumber, so every number reaches the
// handler as float64 and the integer literals are indistinguishable from
// `123.0` / `4.0` by the time this runs. The port renders an integral float64
// with the integer spelling — the reading that matches what JSON encoders
// actually emit for an integer — which is the divergence noted on pyStr.
func TestValidateHandlerInput_StrCoercionOfJSONNumbers(t *testing.T) {
	var body map[string]any
	if err := json.Unmarshal([]byte(`{"repo_url":123,"depth":4,"branch":7.0,"severity_threshold":2.5,"cloud_provider":1e30}`), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	fields := []Field{
		{Name: "repo_url", Type: TypeStr, Required: true},
		{Name: "depth", Type: TypeStr},
		{Name: "branch", Type: TypeStr},
		{Name: "severity_threshold", Type: TypeStr},
		{Name: "cloud_provider", Type: TypeStr},
	}
	got, err := ValidateHandlerInput(body, fields)
	if err != nil {
		t.Fatalf("ValidateHandlerInput: %v", err)
	}

	want := map[string]any{
		"repo_url": "123",
		"depth":    "4",
		// `7.0` is written with an explicit fraction, so Python str()s it
		// "7.0" — but the SDK's decoder erased the literal, and this port
		// resolves the ambiguity toward the integer spelling.
		"branch":             "7",
		"severity_threshold": "2.5",
		"cloud_provider":     "1e+30",
	}
	for name, wantValue := range want {
		if got[name] != wantValue {
			t.Errorf("%s = %#v, want %#v", name, got[name], wantValue)
		}
	}
}

// A string parameter that already carries a string is untouched (str(s) is s),
// and every other scalar keeps Python's repr spelling.
func TestValidateHandlerInput_StrCoercionOfNonNumbers(t *testing.T) {
	got, err := ValidateHandlerInput(
		map[string]any{"a": "already", "b": true, "c": []any{1.0, "x"}},
		[]Field{
			{Name: "a", Type: TypeStr},
			{Name: "b", Type: TypeStr},
			{Name: "c", Type: TypeStr},
		},
	)
	if err != nil {
		t.Fatalf("ValidateHandlerInput: %v", err)
	}
	// Verified against the venv: str(True) == 'True' and
	// str(json.loads('[1, "x"]')) == "[1, 'x']".
	for name, want := range map[string]any{"a": "already", "b": "True", "c": `[1, 'x']`} {
		if got[name] != want {
			t.Errorf("%s = %#v, want %#v", name, got[name], want)
		}
	}
}
