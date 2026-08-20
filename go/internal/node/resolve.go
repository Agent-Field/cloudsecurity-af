package node

// resolve.go ports the two repo-resolution helpers in src/cloudsecurity_af/app.py
// (_workspaces_root and _resolve_repo). They run BEFORE the orchestrator's
// try/except in _run_pipeline, so every failure here is an uncaught exception in
// Python — see runPipeline for how that maps to a status code.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/util"
)

// git subprocess timeouts, matching app.py's subprocess.run(..., timeout=…).
const (
	gitPullTimeout  = 60 * time.Second
	gitCloneTimeout = 120 * time.Second
)

// remotePrefixes is the tuple _resolve_repo tests with str.startswith, IN ORDER.
var remotePrefixes = []string{"https://", "http://", "git@"}

// defaultWorkspacesDir is the `default = "/workspaces"` probe target. It is a
// var ONLY so the test suite can redirect the probe at a temp path instead of
// creating (or refusing to create) a real /workspaces on the developer's
// machine. Production code must never reassign it.
var defaultWorkspacesDir = "/workspaces"

// workspacesFallbackSegments is Python's
// `os.path.join(Path.home(), ".sec-af", "workspaces")`.
//
// Python parity (deliberate oddity, NOT a typo on our side): cloudsecurity-af
// reuses sec-af's fallback directory name — and its SEC_AF_WORKSPACES_DIR env
// var below. Both are copied verbatim from app.py; renaming them would silently
// relocate every already-cloned workspace on an upgraded node.
var workspacesFallbackSegments = []string{".sec-af", "workspaces"}

// workspacesRoot ports app.py::_workspaces_root.
//
// Python:
//
//	explicit = os.environ.get("SEC_AF_WORKSPACES_DIR")
//	if explicit:
//	    os.makedirs(explicit, exist_ok=True)
//	    return explicit
//	default = "/workspaces"
//	try:
//	    os.makedirs(default, exist_ok=True)
//	    test_file = os.path.join(default, ".write_test")
//	    with open(test_file, "w") as f: f.write("")
//	    os.remove(test_file)
//	    return default
//	except OSError:
//	    fallback = os.path.join(Path.home(), ".sec-af", "workspaces")
//	    os.makedirs(fallback, exist_ok=True)
//	    return fallback
//
// Python parity: the explicit branch is a TRUTHINESS test, so
// SEC_AF_WORKSPACES_DIR="" falls through to the /workspaces probe.
//
// Python parity: an mkdir failure in the EXPLICIT branch and in the FALLBACK
// branch propagates (neither is inside the try); only the /workspaces probe is
// guarded, and only against OSError. Both propagating cases return an error here.
//
// Python parity: the probe writes and deletes "/workspaces/.write_test" —
// mkdir succeeding is not enough, the directory must be writable by this user.
func workspacesRoot() (string, error) {
	if explicit := os.Getenv("SEC_AF_WORKSPACES_DIR"); explicit != "" {
		if err := os.MkdirAll(explicit, 0o777); err != nil {
			return "", err
		}
		return explicit, nil
	}

	if err := probeWritableDir(defaultWorkspacesDir); err == nil {
		return defaultWorkspacesDir, nil
	}

	fallback, err := workspacesFallbackDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(fallback, 0o777); err != nil {
		return "", err
	}
	return fallback, nil
}

// workspacesFallbackDir builds `os.path.join(Path.home(), ".sec-af", "workspaces")`.
func workspacesFallbackDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cloudsecurity node: resolve home directory: %w", err)
	}
	return filepath.Join(append([]string{home}, workspacesFallbackSegments...)...), nil
}

// probeWritableDir is the guarded body of _workspaces_root's try block: create
// the directory, then prove it is writable by creating and removing
// "<dir>/.write_test".
func probeWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	testFile := filepath.Join(dir, ".write_test")
	f, err := os.Create(testFile)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(testFile)
}

// resolveRepo ports app.py::_resolve_repo.
//
// Python:
//
//	if os.path.isdir(repo_url): return str(Path(repo_url).resolve())
//	if repo_url.startswith(("https://", "http://", "git@")):
//	    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
//	    ws_root = _workspaces_root()
//	    target_dir = os.path.join(ws_root, repo_name)
//	    os.makedirs(ws_root, exist_ok=True)
//	    if os.path.isdir(target_dir):
//	        subprocess.run(["git","pull","--ff-only"], cwd=target_dir, env=…, timeout=60, capture_output=True)
//	        return target_dir
//	    result = subprocess.run(["git","clone","--depth","1",repo_url,target_dir], env=…, timeout=120, capture_output=True, text=True)
//	    if result.returncode != 0: raise ValueError(f"git clone failed: {result.stderr.strip()}")
//	    return target_dir
//	return str(Path(os.getenv("CLOUDSECURITY_REPO_PATH", os.getcwd())).resolve())
//
// Python parity: the `git pull` RESULT is DISCARDED — `subprocess.run` without
// check=True returns a CompletedProcess for a non-zero exit, so a failed
// refresh (offline, diverged branch, dirty tree) silently reuses the stale
// checkout. That is true ONLY for a non-zero exit: `timeout=60` RAISES
// subprocess.TimeoutExpired and a missing git binary raises FileNotFoundError,
// and both propagate out of _resolve_repo — which app.py:219 calls one line
// ABOVE _run_pipeline's try — so the Python node answers 500 and scans nothing.
// Discarding those in Go would audit a stale checkout and answer 200 with a
// full CloudSecurityScanResult, i.e. present an N-days-old audit as a current
// one. See the pull branch below for how the two are told apart.
//
// Python parity: repo_name strips a trailing "/" then takes the last path
// segment and removes EVERY occurrence of ".git" in it, not just a suffix — so
// "https://host/.gitfoo.git" becomes "foo". Reproduced with ReplaceAll.
//
// DIVERGENCE (message text only): for the CLONE, Python's subprocess timeout
// raises TimeoutExpired while Go's context deadline surfaces as a killed child,
// which this function reports as the "git clone failed: …" ValueError string.
// Both are uncaught in app.py (this helper runs before _run_pipeline's try), so
// both render as a 500 — only the text differs. The clone branch folds the
// underlying error into that text whenever git wrote nothing to stderr, so a
// missing binary or a fired deadline still names its cause instead of
// producing an empty "git clone failed: ".
func resolveRepo(ctx context.Context, repoURL string) (string, error) {
	if isDir(repoURL) {
		return util.ResolvePath(repoURL), nil
	}

	if hasRemotePrefix(repoURL) {
		repoName := repoNameFromURL(repoURL)
		wsRoot, err := workspacesRoot()
		if err != nil {
			return "", err
		}
		targetDir := filepath.Join(wsRoot, repoName)
		if err := os.MkdirAll(wsRoot, 0o777); err != nil {
			return "", err
		}

		if isDir(targetDir) {
			pullCtx, cancel := context.WithTimeout(ctx, gitPullTimeout)
			defer cancel()
			pull := exec.CommandContext(pullCtx, "git", "pull", "--ff-only")
			pull.Dir = targetDir
			pull.Env = gitEnv()
			err := pull.Run()
			if ctxErr := pullCtx.Err(); ctxErr != nil {
				// The 60s deadline (or the caller's cancellation) killed git:
				// Python's `timeout=60` raises subprocess.TimeoutExpired, which
				// propagates. The deadline has to be read off the CONTEXT, not
				// off err — CommandContext reports the kill as an *exec.ExitError
				// ("signal: killed"), indistinguishable from an ordinary
				// non-zero exit.
				return "", ctxErr
			}
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					// git missing or not executable: Python's subprocess.run
					// raises FileNotFoundError, which propagates too.
					return "", err
				}
				// Python parity: `check` defaults to False, so a NON-ZERO EXIT
				// is a normal outcome — the CompletedProcess is discarded and
				// the existing checkout comes back unchanged.
			}
			return targetDir, nil
		}

		cloneCtx, cancel := context.WithTimeout(ctx, gitCloneTimeout)
		defer cancel()
		clone := exec.CommandContext(cloneCtx, "git", "clone", "--depth", "1", repoURL, targetDir)
		clone.Env = gitEnv()
		var stderr strings.Builder
		clone.Stderr = &stderr
		if err := clone.Run(); err != nil {
			// Python parity: the message is `git clone failed: {result.stderr.strip()}`,
			// so an ordinary auth/404 failure keeps git's own text byte for byte.
			// When git wrote NOTHING — the binary is missing (`exec: "git":
			// executable file not found in $PATH`, where Python raises
			// FileNotFoundError) or the 120s deadline killed it before any
			// output — the Python message still names the cause and an empty
			// stderr would not, so err fills in.
			detail := strings.TrimSpace(stderr.String())
			if detail == "" {
				detail = err.Error()
			}
			return "", fmt.Errorf("git clone failed: %s", detail)
		}
		return targetDir, nil
	}

	// Python parity: os.getenv substitutes the cwd only when the key is ABSENT,
	// so CLOUDSECURITY_REPO_PATH="" yields Path("") == Path(".") -> the cwd
	// anyway. util.ResolvePath("") does the same.
	raw, present := os.LookupEnv("CLOUDSECURITY_REPO_PATH")
	if !present {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("cloudsecurity node: resolve repo path: %w", err)
		}
		raw = cwd
	}
	return util.ResolvePath(raw), nil
}

// gitEnv reproduces `{**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}`:
// the process environment plus the two settings that make a missing credential
// fail fast instead of blocking on an interactive prompt.
func gitEnv() []string {
	return append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=echo")
}

// isDir ports os.path.isdir: true only for an existing DIRECTORY (symlinks
// followed), false for a regular file and for anything that does not exist.
func isDir(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// hasRemotePrefix ports `repo_url.startswith(("https://", "http://", "git@"))`.
func hasRemotePrefix(repoURL string) bool {
	for _, prefix := range remotePrefixes {
		if strings.HasPrefix(repoURL, prefix) {
			return true
		}
	}
	return false
}

// repoNameFromURL ports `repo_url.rstrip("/").split("/")[-1].replace(".git", "")`.
//
// Python parity: str.rstrip("/") strips EVERY trailing slash, not just one.
func repoNameFromURL(repoURL string) string {
	trimmed := strings.TrimRight(repoURL, "/")
	last := trimmed
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		last = trimmed[i+1:]
	}
	return strings.ReplaceAll(last, ".git", "")
}
