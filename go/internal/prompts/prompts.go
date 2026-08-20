// Package prompts serves the LLM prompt templates that the cloudsecurity-af
// agents interpolate and hand to the harness.
//
// The files under files/ are BYTE-IDENTICAL copies of
// src/cloudsecurity_af/prompts/**, laid out with the same relative paths, so
// "recon/iac_reader.txt" names the same template on both sides. The Python
// agents read theirs at call time:
//
//	PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "recon" / "iac_reader.txt"
//	prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
//
// The Go port embeds them into the binary instead, which is what makes the
// single static binary self-contained (the Python package has to ship the
// prompts/ tree as package data). prompts_drift_test.go re-verifies the copies
// against the Python tree whenever the checkout contains it, so the two can
// never silently diverge.
//
// The embed directive, given a bare directory name, walks it recursively and
// skips names beginning with "." or "_"; every prompt path here is plain, so
// the whole tree is embedded.
package prompts

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed files
var files embed.FS

// Load returns the prompt template at rel — a slash-separated path relative to
// the prompts root, e.g. "recon/iac_reader.txt" — or an error when no such
// template is embedded.
//
// Python parity: the Python agents call Path.read_text() at INVOCATION time, so
// a missing template surfaces as a FileNotFoundError inside the reasoner (a
// failed execution), not at import. Load's error return is the faithful
// equivalent for a caller that wants to map the failure onto a reasoner error;
// MustLoad is for package-level template constants.
func Load(rel string) (string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(rel, "\\", "/"))[1:]
	b, err := files.ReadFile("files/" + clean)
	if err != nil {
		return "", fmt.Errorf("prompts: no embedded template %q", rel)
	}
	return string(b), nil
}

// MustLoad is Load for call sites where a missing template is a programmer
// error rather than a runtime condition: the file set is fixed at compile time
// by go:embed, so a failure here means the constant path was mistyped and no
// amount of retrying will help. It panics.
func MustLoad(rel string) string {
	s, err := Load(rel)
	if err != nil {
		panic(err)
	}
	return s
}

// Names lists every embedded template path (slash-separated, relative to the
// prompts root) in sorted order. Used by the drift test and useful for
// diagnostics.
func Names() []string {
	var out []string
	_ = fs.WalkDir(files, "files", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		out = append(out, strings.TrimPrefix(p, "files/"))
		return nil
	})
	sort.Strings(out)
	return out
}
