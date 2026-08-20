package prompts

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// pythonPromptRoot is the Python source of truth, relative to THIS package
// directory (go/internal/prompts -> ../../../ is the repo root).
const pythonPromptRoot = "../../../src/cloudsecurity_af/prompts"

// TestPromptsMatchThePythonTree is the anti-drift gate for the whole port: the
// embedded templates under files/ must be byte-identical to
// src/cloudsecurity_af/prompts/**, with the same relative layout and NO file
// present on one side only.
//
// The port contract says prompts are byte-verbatim; a whitespace-level edit on
// either side changes what the LLM sees and silently breaks parity, so this
// walks BOTH trees and compares in both directions.
//
// It is skipped when the Python tree is absent, which is the case for a
// module-only checkout (e.g. `go install`-ing the module, or a Docker build
// stage that copies only go/).
func TestPromptsMatchThePythonTree(t *testing.T) {
	info, err := os.Stat(pythonPromptRoot)
	if err != nil || !info.IsDir() {
		t.Skipf("Python prompt tree not present at %s — module-only checkout", pythonPromptRoot)
	}

	pythonFiles := map[string][]byte{}
	err = filepath.Walk(pythonPromptRoot, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(pythonPromptRoot, p)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		pythonFiles[filepath.ToSlash(rel)] = body
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", pythonPromptRoot, err)
	}
	if len(pythonFiles) == 0 {
		t.Fatalf("no prompt files found under %s", pythonPromptRoot)
	}

	embedded := Names()
	pythonNames := make([]string, 0, len(pythonFiles))
	for name := range pythonFiles {
		pythonNames = append(pythonNames, name)
	}
	sort.Strings(pythonNames)

	// Direction 1: every Python template is embedded, with identical bytes.
	for _, name := range pythonNames {
		got, err := Load(name)
		if err != nil {
			t.Errorf("prompt %q exists in the Python tree but is NOT embedded", name)
			continue
		}
		if !bytes.Equal([]byte(got), pythonFiles[name]) {
			t.Errorf("prompt %q differs from the Python source (%d embedded bytes vs %d Python bytes)",
				name, len(got), len(pythonFiles[name]))
		}
	}

	// Direction 2: nothing is embedded that the Python tree does not have.
	for _, name := range embedded {
		if _, ok := pythonFiles[name]; !ok {
			t.Errorf("prompt %q is embedded but does NOT exist in the Python tree", name)
		}
	}
}
