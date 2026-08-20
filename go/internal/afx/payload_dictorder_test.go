package afx

import (
	"encoding/json"
	"testing"
)

type orderedDictModel struct {
	Name    string             `json:"name"`
	Counts  map[string]int     `json:"counts"`
	Costs   map[string]float64 `json:"costs"`
	Untamed map[string]int     `json:"untamed"`
}

func (orderedDictModel) DictFieldOrder() map[string][]string {
	return map[string][]string{
		"counts": {"critical", "high", "medium", "low", "info"},
		"costs":  {"recon", "hunt"},
	}
}

// VALIDATION CONTRACT — Dump renders a declared dict field in the model's
// stated INSERTION order, not alphabetically.
//
// Python dicts keep insertion order and json.dumps honors it, so
// `{s.value: 0 for s in Severity}` reaches the wire as
// critical/high/medium/low/info. Every field NOT named by DictFieldOrder keeps
// the sorted rendering, which is pyfmt.Dumps' documented map deviation.
func TestDump_DictFieldOrderBeatsTheMapSort(t *testing.T) {
	p, err := Dump(orderedDictModel{
		Name:    "n",
		Counts:  map[string]int{"info": 5, "critical": 1, "low": 4, "high": 2, "medium": 3},
		Costs:   map[string]float64{"hunt": 2, "recon": 1},
		Untamed: map[string]int{"b": 2, "a": 1},
	})
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"name":"n","counts":{"critical":1,"high":2,"medium":3,"low":4,"info":5},"costs":{"recon":1.0,"hunt":2.0},"untamed":{"a":1,"b":2}}`
	if string(body) != want {
		t.Errorf("body = %s\nwant  %s", body, want)
	}
}

// A key the declared order does not name is kept, sorted, after the known ones
// — never dropped. A nil map still renders null, as pydantic would.
func TestDump_DictFieldOrderKeepsUnknownKeysAndNilMaps(t *testing.T) {
	p, err := Dump(orderedDictModel{Counts: map[string]int{"zzz": 9, "high": 2, "aaa": 1}})
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"name":"","counts":{"high":2,"aaa":1,"zzz":9},"costs":null,"untamed":null}`
	if string(body) != want {
		t.Errorf("body = %s\nwant  %s", body, want)
	}
}
