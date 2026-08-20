package schemas

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
)

// declaredModels is every struct in this package that ports a pydantic
// BaseModel. afx.Bind applies pydantic's lax scalar coercion and its
// null-rejection to these and to nothing else, so the list IS the contract.
var declaredModels = []any{
	// recon.py
	Variable{}, Output{}, ProviderConfig{}, Module{}, Resource{},
	ResourceInventory{}, ResourceGraph{}, ConfigDiff{}, DriftedResource{},
	DriftReport{}, ReconResult{},
	// hunt.py
	AffectedResource{}, RawFinding{}, HuntResult{},
	// chain.py
	AttackStep{}, BlastRadius{}, AttackPath{}, ChainResult{},
	// prove.py
	Proof{}, IaCDiff{}, RemediationSuggestion{}, VerifiedFinding{},
	// input.py
	CloudConfig{}, CloudSecurityInput{},
	// output.py
	CloudSecurityScanResult{}, ScanProgress{}, ScanMetrics{},
	// views.py
	FindingForDedup{}, FindingForProver{}, FindingForChain{},
	// agents/chain/path_constructor.py
	ChildInvestigation{}, PathInvestigationPlan{},
}

// notAModel is every exported struct here that is deliberately NOT a pydantic
// model. Timestamp is the `datetime` scalar wrapper — an opaque leaf with its
// own UnmarshalJSON, not a BaseModel.
var notAModel = map[string]bool{"Timestamp": true}

func TestPydanticModel_EveryDeclaredModelIsMarked(t *testing.T) {
	for _, m := range declaredModels {
		if _, ok := m.(afx.PydanticModel); !ok {
			t.Errorf("%T does not implement afx.PydanticModel; add it to model.go", m)
		}
	}
}

// COVERAGE GUARD: a new exported model struct added to this package without a
// PydanticModel() line in model.go would silently bind with encoding/json's
// rules instead of pydantic's. Parsing the package sources is the only way to
// see a type Go reflection cannot enumerate.
func TestPydanticModel_NoExportedModelStructIsUnmarked(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				return true
			}
			if _, isStruct := ts.Type.(*ast.StructType); isStruct {
				found[ts.Name.Name] = true
			}
			return true
		})
	}

	declared := map[string]bool{}
	for _, m := range declaredModels {
		declared[reflect.TypeOf(m).Name()] = true
	}
	var unmarked []string
	for name := range found {
		if !declared[name] && !notAModel[name] {
			unmarked = append(unmarked, name)
		}
	}
	sort.Strings(unmarked)
	if len(unmarked) > 0 {
		t.Fatalf("exported struct(s) %v are neither declared models nor listed in notAModel:\n"+
			"add a PydanticModel() line in model.go (and a row in declaredModels), or\n"+
			"record why the type is not a pydantic model", unmarked)
	}
	// The reverse direction: a model that was deleted must leave the list.
	for name := range declared {
		if !found[name] {
			t.Errorf("declaredModels names %s, which this package no longer declares", name)
		}
	}
}
