package afx

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// required.go restores the half of `Model.model_validate(payload)` that a JSON
// round-trip silently drops: pydantic raises `ValidationError` when a field
// WITHOUT a default is absent, while encoding/json leaves it at the Go zero
// value and reports success.
//
// That gap is reachable on every phase boundary. recon_phase does
//
//	inventory = ResourceInventory.model_validate(_as_dict(_unwrap(iac_raw, ...)))
//
// and `inventory_saved_path` is required, so a malformed iac-reader reply
// aborts the phase in Python; binding it to "" instead carries an empty path
// into run_resource_graph_builder. prove_phase relies on the same raise to take
// its `_fallback_verified(finding, "Schema parse failed: ...")` branch — a
// prover reply missing `verdict`/`severity` must become an INCONCLUSIVE
// finding with drop_reason "prover_error", not a finding whose verdict is ""
// (uncounted in the verdict tallies, a bogus "" key in by_severity, and dropped
// outright by the default severity_threshold because "" has no rank).
//
// A model declares its required fields with RequiredFields; the list is the
// transcription of `[n for n, f in Model.model_fields.items() if f.is_required()]`
// and internal/schemas' test cross-checks every declared list against the
// committed pydantic schema fixtures' `required` arrays.

// RequiredFielder is implemented by the ported pydantic models that have at
// least one field without a default.
type RequiredFielder interface {
	RequiredFields() []string
}

// MissingFieldError is the Go stand-in for pydantic's ValidationError with
// `type=missing`.
//
// DIVERGENCE (message text only): pydantic's rendering carries the offending
// input value and a docs URL — "1 validation error for ResourceInventory\n
// inventory_saved_path\n  Field required [type=missing, input_value={}, ...]".
// The Go text keeps the model name, the count and the field list, which is what
// the phases surface (prove_phase embeds it in the fallback's evidence string).
type MissingFieldError struct {
	Model  string
	Fields []string
}

func (e *MissingFieldError) Error() string {
	plural := "s"
	if len(e.Fields) == 1 {
		plural = ""
	}
	return fmt.Sprintf("%d validation error%s for %s: %s: Field required",
		len(e.Fields), plural, e.Model, strings.Join(e.Fields, ", "))
}

// requireFields walks the untyped payload alongside the Go type t and reports
// the first model whose required fields are not all present, the way pydantic
// validates a nested model tree rather than only the outer object.
func requireFields(payload any, t reflect.Type) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return nil
	}

	switch value := payload.(type) {
	case map[string]any:
		if t.Kind() == reflect.Map {
			// dict[str, V]: the KEYS are data, the values may be models.
			for _, v := range value {
				if err := requireFields(v, t.Elem()); err != nil {
					return err
				}
			}
			return nil
		}
		if t.Kind() != reflect.Struct {
			return nil
		}
		if err := checkModelRequired(value, t); err != nil {
			return err
		}
		fields := jsonFieldTypes(t)
		// Deterministic order so the reported field is stable run to run.
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ft, declared := fields[k]
			if !declared {
				continue
			}
			if err := requireFields(value[k], ft); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
			return nil
		}
		for _, e := range value {
			if err := requireFields(e, t.Elem()); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

// checkModelRequired reports the required fields of t that payload does not
// carry. Python parity: pydantic's `missing` fires on an ABSENT key; a key
// present with an explicit null is a different (type) error, and this port
// leaves that one to the decode.
func checkModelRequired(payload map[string]any, t reflect.Type) error {
	rf, ok := reflect.New(t).Interface().(RequiredFielder)
	if !ok {
		return nil
	}
	var missing []string
	for _, name := range rf.RequiredFields() {
		if _, present := payload[name]; !present {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &MissingFieldError{Model: t.Name(), Fields: missing}
}
