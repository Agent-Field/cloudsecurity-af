package node

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/util"
)

// TestRepoNameFromURL_MatchesPython pins
// `repo_url.rstrip("/").split("/")[-1].replace(".git", "")`. Every expectation
// was produced by running that expression under the repo's own interpreter
// (~/.agentfield/packages/cloudsecurity-af/venv/bin/python).
func TestRepoNameFromURL_MatchesPython(t *testing.T) {
	cases := []struct{ url, want string }{
		{"https://github.com/owner/repo.git", "repo"},
		{"https://github.com/owner/repo", "repo"},
		{"https://github.com/owner/repo///", "repo"},
		{"git@github.com:owner/repo.git", "repo"},
		// replace() is not a suffix strip: EVERY ".git" in the last segment goes.
		{"http://host/a/b/.gitfoo.git", "foo"},
		{"https://github.com/owner/my.github.repo.git", "myhub.repo"},
	}
	for _, tc := range cases {
		if got := repoNameFromURL(tc.url); got != tc.want {
			t.Errorf("repoNameFromURL(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestHasRemotePrefix(t *testing.T) {
	for _, url := range []string{"https://x/y", "http://x/y", "git@host:o/r.git"} {
		if !hasRemotePrefix(url) {
			t.Errorf("hasRemotePrefix(%q) = false", url)
		}
	}
	for _, url := range []string{"", "/abs/path", "ssh://host/x", "ftp://x"} {
		if hasRemotePrefix(url) {
			t.Errorf("hasRemotePrefix(%q) = true", url)
		}
	}
}

// --- _workspaces_root --------------------------------------------------------

func TestWorkspacesRoot_ExplicitEnvIsCreatedAndReturned(t *testing.T) {
	explicit := filepath.Join(t.TempDir(), "nested", "ws")
	t.Setenv("SEC_AF_WORKSPACES_DIR", explicit)

	got, err := workspacesRoot()
	if err != nil {
		t.Fatalf("workspacesRoot: %v", err)
	}
	if got != explicit {
		t.Fatalf("workspacesRoot() = %q, want %q", got, explicit)
	}
	if !isDir(explicit) {
		t.Fatal("explicit workspaces dir was not created")
	}
}

// TestWorkspacesRoot_EmptyEnvFallsThrough pins Python's TRUTHINESS test:
// SEC_AF_WORKSPACES_DIR="" is not an explicit override, so the /workspaces
// probe runs (redirected here so the test never touches the real /workspaces).
func TestWorkspacesRoot_EmptyEnvFallsThrough(t *testing.T) {
	t.Setenv("SEC_AF_WORKSPACES_DIR", "")
	probe := filepath.Join(t.TempDir(), "workspaces")
	withDefaultWorkspacesDir(t, probe)

	got, err := workspacesRoot()
	if err != nil {
		t.Fatalf("workspacesRoot: %v", err)
	}
	if got != probe {
		t.Fatalf("workspacesRoot() = %q, want the probe target %q", got, probe)
	}
	if !isDir(probe) {
		t.Fatal("the probe target was not created")
	}
}

// TestWorkspacesRoot_FallbackWhenDefaultIsUnwritable exercises the
// except-OSError branch: the probe target cannot be created (a regular file is
// in the way), so the root becomes $HOME/.sec-af/workspaces — sec-af, verbatim
// from app.py.
func TestWorkspacesRoot_FallbackWhenDefaultIsUnwritable(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	withDefaultWorkspacesDir(t, filepath.Join(blocker, "workspaces"))

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SEC_AF_WORKSPACES_DIR", "")

	got, err := workspacesRoot()
	if err != nil {
		t.Fatalf("workspacesRoot: %v", err)
	}
	want := filepath.Join(home, ".sec-af", "workspaces")
	if got != want {
		t.Fatalf("workspacesRoot() = %q, want %q", got, want)
	}
	if !isDir(want) {
		t.Fatal("fallback workspaces dir was not created")
	}
}

// TestWorkspacesRoot_ProbeIsWritabilityNotExistence pins the .write_test probe:
// a directory that exists but cannot be written to must NOT be accepted.
func TestWorkspacesRoot_ProbeIsWritabilityNotExistence(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0500 directory is still writable")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := probeWritableDir(dir); err == nil {
		t.Fatal("probeWritableDir accepted a non-writable directory")
	}
	if _, err := os.Stat(filepath.Join(dir, ".write_test")); !os.IsNotExist(err) {
		t.Fatal("the probe left .write_test behind")
	}
}

// --- _resolve_repo -----------------------------------------------------------

func TestResolveRepo_ExistingDirectoryIsResolvedInPlace(t *testing.T) {
	dir := t.TempDir()
	got, err := resolveRepo(context.Background(), dir)
	if err != nil {
		t.Fatalf("resolveRepo: %v", err)
	}
	if got != util.ResolvePath(dir) {
		t.Fatalf("resolveRepo(%q) = %q, want %q", dir, got, util.ResolvePath(dir))
	}
}

// TestResolveRepo_NonURLNonDirUsesRepoPathEnv pins the final fallback branch.
func TestResolveRepo_NonURLNonDirUsesRepoPathEnv(t *testing.T) {
	repo := t.TempDir()
	t.Setenv("CLOUDSECURITY_REPO_PATH", repo)

	got, err := resolveRepo(context.Background(), "not-a-path-and-not-a-url")
	if err != nil {
		t.Fatalf("resolveRepo: %v", err)
	}
	if got != util.ResolvePath(repo) {
		t.Fatalf("resolveRepo() = %q, want %q", got, util.ResolvePath(repo))
	}
}

// TestResolveRepo_NonURLNonDirFallsBackToCwd pins `os.getenv(..., os.getcwd())`.
func TestResolveRepo_NonURLNonDirFallsBackToCwd(t *testing.T) {
	_ = os.Unsetenv("CLOUDSECURITY_REPO_PATH")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	got, err := resolveRepo(context.Background(), "definitely-not-here")
	if err != nil {
		t.Fatalf("resolveRepo: %v", err)
	}
	if got != util.ResolvePath(cwd) {
		t.Fatalf("resolveRepo() = %q, want %q", got, util.ResolvePath(cwd))
	}
}

// TestResolveRepo_ClonesIntoTheWorkspacesRoot drives the http(s)/git@ branch
// against a real local git repository served over a file path URL. It proves
// the target directory layout (<ws_root>/<repo_name>) and that a second call
// reuses the checkout instead of re-cloning.
func TestResolveRepo_ClonesIntoTheWorkspacesRootAndReusesIt(t *testing.T) {
	requireGit(t)

	origin := filepath.Join(t.TempDir(), "origin")
	initGitRepo(t, origin)

	ws := t.TempDir()
	t.Setenv("SEC_AF_WORKSPACES_DIR", ws)

	// resolveRepo only clones for https://, http:// or git@ URLs; a file path
	// would take the isdir branch. Use an http:// URL shape that git can
	// resolve through the insteadOf rewrite below.
	url := "https://example.invalid/owner/origin.git"
	rewriteRemote(t, url, origin)

	got, err := resolveRepo(context.Background(), url)
	if err != nil {
		t.Fatalf("resolveRepo: %v", err)
	}
	want := filepath.Join(ws, "origin")
	if got != want {
		t.Fatalf("resolveRepo() = %q, want %q", got, want)
	}
	if !isDir(filepath.Join(want, ".git")) {
		t.Fatal("clone did not produce a git checkout")
	}

	// Second call: the target exists, so Python runs `git pull --ff-only` and
	// returns the same directory — no re-clone, and a pull failure is ignored.
	marker := filepath.Join(want, "marker")
	if err := os.WriteFile(marker, []byte("kept"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	again, err := resolveRepo(context.Background(), url)
	if err != nil {
		t.Fatalf("resolveRepo (reuse): %v", err)
	}
	if again != want {
		t.Fatalf("resolveRepo (reuse) = %q, want %q", again, want)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the existing checkout was replaced instead of reused")
	}
}

// TestResolveRepo_CloneFailureIsAValueErrorString pins the message app.py
// raises: `git clone failed: {result.stderr.strip()}`. The remote is rewritten
// (git insteadOf) onto a local path that does not exist, so the failure is
// deterministic and offline.
func TestResolveRepo_CloneFailureIsAValueErrorString(t *testing.T) {
	requireGit(t)

	ws := t.TempDir()
	t.Setenv("SEC_AF_WORKSPACES_DIR", ws)

	url := "https://example.invalid/owner/nope.git"
	rewriteRemote(t, url, filepath.Join(t.TempDir(), "does-not-exist"))

	_, err := resolveRepo(context.Background(), url)
	if err == nil {
		t.Fatal("expected a clone failure")
	}
	if !strings.HasPrefix(err.Error(), "git clone failed: ") {
		t.Fatalf("error = %q, want the \"git clone failed: \" prefix", err)
	}
	detail := strings.TrimPrefix(err.Error(), "git clone failed: ")
	if detail == "" || detail != strings.TrimSpace(detail) {
		t.Fatalf("stderr was not stripped: %q", err)
	}
}

// --- helpers -----------------------------------------------------------------

// withDefaultWorkspacesDir redirects the /workspaces probe for one test.
func withDefaultWorkspacesDir(t *testing.T, dir string) {
	t.Helper()
	previous := defaultWorkspacesDir
	defaultWorkspacesDir = dir
	t.Cleanup(func() { defaultWorkspacesDir = previous })
}

// rewriteRemote makes git resolve url to a local path, so the clone branch of
// _resolve_repo can be exercised without a network.
func rewriteRemote(t *testing.T, url, localPath string) {
	t.Helper()
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "url."+localPath+".insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", url)
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("# empty\n"), 0o644); err != nil {
		t.Fatalf("write main.tf: %v", err)
	}
	for _, args := range [][]string{
		{"init", "--initial-branch=main"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
		{"add", "."},
		{"commit", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v failed (%v): %s", args, err, out)
		}
	}
}

// TestResolveRepo_PullDeadlineIsNotSwallowed pins the ONE `git pull` outcome
// _resolve_repo does not discard.
//
// `subprocess.run(["git","pull","--ff-only"], …, timeout=60)` returns a
// CompletedProcess for a non-zero exit (check defaults to False, so the stale
// checkout is silently reused) but RAISES subprocess.TimeoutExpired when the
// deadline fires — verified on the repo's own interpreter:
//
//	subprocess.run(["sleep","3"], timeout=0.5)  ->  TimeoutExpired
//
// _resolve_repo is called at app.py:219, one line ABOVE _run_pipeline's `try`,
// so that exception is uncaught and the Python node answers 500. Swallowing it
// in Go audits a checkout as it was N days ago and answers 200 with a full
// CloudSecurityScanResult — a stale audit presented as a current one.
//
// The cancelled context stands in for the fired 60s deadline: both make
// pullCtx.Err() non-nil and both make CommandContext kill the child, which
// Run() reports as an indistinguishable *exec.ExitError.
func TestResolveRepo_PullDeadlineIsNotSwallowed(t *testing.T) {
	requireGit(t)

	ws := t.TempDir()
	t.Setenv("SEC_AF_WORKSPACES_DIR", ws)
	// The pull branch is taken when the target directory already exists.
	if err := os.MkdirAll(filepath.Join(ws, "myrepo"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := resolveRepo(ctx, "https://example.invalid/owner/myrepo.git")
	if err == nil {
		t.Fatalf("resolveRepo returned %q with no error; a killed pull must "+
			"propagate the way subprocess.TimeoutExpired does", got)
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context error", err)
	}
}

// TestResolveRepo_PullExitCodeIsStillDiscarded is the other half of the
// contract: `check` defaults to False, so an ordinary FAILED pull (no remote
// configured here, so `git pull` exits non-zero) must still return the existing
// checkout, unchanged.
func TestResolveRepo_PullExitCodeIsStillDiscarded(t *testing.T) {
	requireGit(t)

	ws := t.TempDir()
	t.Setenv("SEC_AF_WORKSPACES_DIR", ws)
	target := filepath.Join(ws, "myrepo")
	initGitRepo(t, target)

	got, err := resolveRepo(context.Background(), "https://example.invalid/owner/myrepo.git")
	if err != nil {
		t.Fatalf("resolveRepo: %v — a non-zero pull exit is discarded in Python", err)
	}
	if got != target {
		t.Fatalf("resolveRepo() = %q, want %q", got, target)
	}
}

// TestResolveRepo_CloneFailureNamesItsCauseWhenGitIsSilent pins the second half
// of `git clone failed: {result.stderr.strip()}`.
//
// Python's subprocess.run raises FileNotFoundError("[Errno 2] No such file or
// directory: 'git'") when the binary is missing, so the 500 body names the
// cause. Go's exec fails BEFORE the child starts, leaving stderr empty — the
// message used to be the content-free "git clone failed: ". The underlying
// error fills in exactly when git wrote nothing, so an ordinary auth/404
// failure keeps Python's byte-for-byte stderr text (pinned by
// TestResolveRepo_CloneFailureIsAValueErrorString above).
func TestResolveRepo_CloneFailureNamesItsCauseWhenGitIsSilent(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("SEC_AF_WORKSPACES_DIR", ws)
	// An empty PATH makes exec.Command fail to find git at all.
	t.Setenv("PATH", filepath.Join(t.TempDir(), "empty"))

	_, err := resolveRepo(context.Background(), "https://example.invalid/owner/nope.git")
	if err == nil {
		t.Fatal("expected a clone failure")
	}
	if !strings.HasPrefix(err.Error(), "git clone failed: ") {
		t.Fatalf("error = %q, want the \"git clone failed: \" prefix", err)
	}
	detail := strings.TrimPrefix(err.Error(), "git clone failed: ")
	if detail == "" {
		t.Fatalf("error = %q — the cause was dropped; Python names the missing binary", err)
	}
	if !strings.Contains(detail, "git") {
		t.Errorf("detail = %q, want it to name the executable", detail)
	}
}
