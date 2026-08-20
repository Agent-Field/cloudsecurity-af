package util

import (
	"os"
	"path/filepath"
)

// ResolvePath ports Python's `str(Path(p).resolve())` (pathlib, non-strict —
// the 3.6+ default).
//
// This is an ADDITION, not a port of anything in _utils.py: the seven HUNT
// agents all compute their harness working directory with
//
//	harness_cwd = str(Path(repo_path).resolve())
//
// and app.py / orchestrator.py resolve the repo path the same way. One
// implementation lives here so the port cannot drift between them.
//
// Semantics, verified against ~/.agentfield/packages/cloudsecurity-af/venv
// (CPython 3.11.12):
//
//	Path("rp/real").resolve()        -> <cwd>/rp/real       relative -> absolute
//	Path("rp/link").resolve()        -> <cwd>/rp/real       symlinks are followed
//	Path("rp/link/").resolve()       -> <cwd>/rp/real       trailing slash dropped
//	Path("rp/nope/deeper").resolve() -> <cwd>/rp/nope/deeper  NON-STRICT: a path
//	                                                          that does not exist
//	                                                          still resolves
//	Path("").resolve()               -> <cwd>               "" is "."
//	Path("/abs/nonexistent/x")       -> /abs/nonexistent/x  unchanged
//
// Implementation: hand the un-Cleaned absolute path to filepath.EvalSymlinks,
// whose walk resolves each component and pops on ".." exactly as realpath(3)
// does. When the path does not exist EvalSymlinks fails, so we resolve the
// longest existing ANCESTOR and re-attach the missing tail — Python's
// non-strict behavior.
//
// DIVERGENCE: in the non-existent-path fallback the tail is joined lexically,
// so a ".." that would have crossed a symlink inside the MISSING part of the
// path is collapsed lexically rather than by walking. No call site constructs
// such a path (they are all repo roots and temp dirs).
func ResolvePath(p string) string {
	abs := p
	if !filepath.IsAbs(abs) {
		if cwd, err := os.Getwd(); err == nil {
			// Deliberately NOT filepath.Join/Abs: those Clean the result,
			// which would collapse ".." lexically BEFORE symlinks are
			// followed. EvalSymlinks does its own Clean at the end.
			abs = cwd + string(filepath.Separator) + abs
		}
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}

	cleaned := filepath.Clean(abs)
	var tail []string
	current := cleaned
	for {
		parent := filepath.Dir(current)
		if parent == current { // reached the root
			return cleaned
		}
		tail = append([]string{filepath.Base(current)}, tail...)
		current = parent
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(append([]string{resolved}, tail...)...)
		}
	}
}
