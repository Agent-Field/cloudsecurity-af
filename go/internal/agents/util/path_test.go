package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The expected values were captured from the repo's own interpreter:
//
//	~/.agentfield/packages/cloudsecurity-af/venv/bin/python
//	>>> from pathlib import Path; str(Path(p).resolve())
//
// with rp/real a directory and rp/link a symlink to it.
func TestResolvePath_MatchesPathlibResolve(t *testing.T) {
	dir := t.TempDir()
	// t.TempDir() can itself sit under a symlink (/tmp -> /private/tmp on
	// macOS, and WSL mount points), so the expectations are anchored on the
	// resolved root rather than on dir itself.
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolving the temp dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "rp", "real"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink("real", filepath.Join(root, "rp", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"existing directory", filepath.Join(root, "rp", "real"), filepath.Join(root, "rp", "real")},
		{"symlink is followed", filepath.Join(root, "rp", "link"), filepath.Join(root, "rp", "real")},
		{"trailing separator", filepath.Join(root, "rp", "link") + "/", filepath.Join(root, "rp", "real")},
		{"dot segments", filepath.Join(root, "rp", "real", "..", "real"), filepath.Join(root, "rp", "real")},
		// NON-STRICT: pathlib resolves a path that does not exist.
		{"missing tail", filepath.Join(root, "rp", "nope", "deeper"), filepath.Join(root, "rp", "nope", "deeper")},
		{"missing tail under a symlink", filepath.Join(root, "rp", "link", "nope"), filepath.Join(root, "rp", "real", "nope")},
		{"fully missing absolute path", "/abs/nonexistent/x", "/abs/nonexistent/x"},
	}
	for _, tc := range cases {
		if got := ResolvePath(tc.in); got != tc.want {
			t.Errorf("%s: ResolvePath(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestResolvePath_RelativePathsResolveAgainstTheWorkingDirectory(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	resolvedCwd, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		t.Fatalf("resolving cwd: %v", err)
	}

	// Python: Path("") is Path("."), so both resolve to the working directory.
	for _, in := range []string{"", "."} {
		if got := ResolvePath(in); got != resolvedCwd {
			t.Errorf("ResolvePath(%q) = %q, want %q", in, got, resolvedCwd)
		}
	}
	if got, want := ResolvePath("testdata"), filepath.Join(resolvedCwd, "testdata"); got != want {
		t.Errorf("ResolvePath(%q) = %q, want %q", "testdata", got, want)
	}
	if got := ResolvePath("no/such/dir"); !strings.HasPrefix(got, resolvedCwd) {
		t.Errorf("ResolvePath(%q) = %q, want it under %q", "no/such/dir", got, resolvedCwd)
	}
}

// The result is always absolute, which is what makes it safe as a harness Cwd.
func TestResolvePath_IsAlwaysAbsolute(t *testing.T) {
	for _, in := range []string{"", ".", "..", "relative/path", "/already/absolute"} {
		if got := ResolvePath(in); !filepath.IsAbs(got) {
			t.Errorf("ResolvePath(%q) = %q, which is not absolute", in, got)
		}
	}
}
