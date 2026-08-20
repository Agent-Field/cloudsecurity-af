package schemas

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
)

// TestEmbeddedSchemasMatchGoStructTags closes the TODO left on
// harnessx.TestEmbeddedSchemas_DecodeAndDescribeAnObject: the JSON schema the
// harness SENDS to the model and the Go struct that RECEIVES the reply have to
// describe the same object.
//
// Why it matters, concretely: harnessx.Run[T] passes the committed fixture as
// the `schema=` argument and decodes the reply into T. If the fixture names a
// property the Go struct has no json tag for, the model is told to produce a
// field encoding/json then silently drops — a whole field of the ported
// pydantic model vanishing with no error anywhere. The reverse (a tag with no
// property) means the Go struct expects something the model was never asked
// for, so the field stays at its zero value on every run.
//
// The check runs over the top-level object of every fixture AND over every
// `$defs` sub-model, so a drift in a nested type (RawFinding inside HuntResult,
// AttackStep inside AttackPath, …) fails here too.
//
// This test lives in internal/schemas rather than internal/harnessx because it
// needs the destination types; harnessx has no dependency on this package and
// must not grow one.
func TestEmbeddedSchemasMatchGoStructTags(t *testing.T) {
	registry := goDefaults()

	names := harnessx.EmbeddedSchemaNames()
	if len(names) == 0 {
		t.Fatal("no embedded schema fixtures found")
	}

	checked := map[string]bool{}
	for _, fixture := range names {
		schema, err := harnessx.LoadEmbeddedSchema(fixture)
		if err != nil {
			t.Fatalf("LoadEmbeddedSchema(%s): %v", fixture, err)
		}

		t.Run(fixture, func(t *testing.T) {
			assertSchemaMatchesStruct(t, registry, fixture, schema, checked)

			defs, _ := schema["$defs"].(map[string]any)
			for defName, raw := range defs {
				sub, ok := raw.(map[string]any)
				if !ok {
					t.Errorf("$defs/%s is %T, want an object", defName, raw)
					continue
				}
				// Enum and scalar $defs describe a value, not a model.
				if _, hasProps := sub["properties"]; !hasProps {
					continue
				}
				t.Run("$defs/"+defName, func(t *testing.T) {
					assertSchemaMatchesStruct(t, registry, defName, sub, checked)
				})
			}
		})
	}

	// The fixtures are the harness contract; if one of them stops covering a
	// model the port sends, that is worth knowing.
	if len(checked) < len(names) {
		t.Errorf("cross-checked %d models from %d fixtures — every fixture must contribute at least its own top-level model", len(checked), len(names))
	}
}

// assertSchemaMatchesStruct compares one JSON-schema object node against the Go
// model registered under the same name.
func assertSchemaMatchesStruct(t *testing.T, registry map[string]any, name string, node map[string]any, checked map[string]bool) {
	t.Helper()

	model, ok := registry[name]
	if !ok {
		t.Fatalf("schema %q has no Go model registered in goDefaults() — every pydantic model the harness sends must have a Go destination", name)
	}
	checked[name] = true

	props, ok := node["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema %q has no properties object", name)
	}
	want := make([]string, 0, len(props))
	for k := range props {
		want = append(want, k)
	}
	sort.Strings(want)

	got := jsonFieldNames(reflect.TypeOf(model))
	sort.Strings(got)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("model %s: json tags and schema properties differ\n  go tags: %v\n  schema : %v\n  only in go: %v\n  only in schema: %v",
			name, got, want, missing(got, want), missing(want, got))
	}

	// Every `required` name must be a real field. pydantic emits `required`
	// only for fields with no default, so an absent key is normal.
	tagSet := map[string]bool{}
	for _, g := range got {
		tagSet[g] = true
	}
	req, _ := node["required"].([]any)
	for _, r := range req {
		s, ok := r.(string)
		if !ok {
			t.Errorf("model %s: required entry %#v is not a string", name, r)
			continue
		}
		if !tagSet[s] {
			t.Errorf("model %s: schema requires %q but the Go struct has no such json tag", name, s)
		}
	}
}

// jsonFieldNames returns the json names encoding/json would emit for t's
// exported fields, flattening anonymous embedded structs the way it does.
func jsonFieldNames(t reflect.Type) []string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	out := []string{}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" && sf.Anonymous {
			inner := sf.Type
			for inner.Kind() == reflect.Pointer {
				inner = inner.Elem()
			}
			if inner.Kind() == reflect.Struct {
				out = append(out, jsonFieldNames(inner)...)
				continue
			}
		}
		if name == "" {
			name = sf.Name
		}
		out = append(out, name)
	}
	return out
}

// missing returns the entries of a that are not in b.
func missing(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range b {
		set[s] = true
	}
	out := []string{}
	for _, s := range a {
		if !set[s] {
			out = append(out, s)
		}
	}
	return out
}
