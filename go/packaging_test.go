package gomod

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This file is the parity gate for the packaging the Go node ships with. Every
// assertion here is derived from what the PYTHON stack does — the repo's own
// Dockerfile, docker-compose.yml and app.py — not from what the Go files
// currently say.
//
// Paths are relative to go/, which is this package's directory.
const (
	goDockerfile  = "Dockerfile"
	goEntrypoint  = "docker-entrypoint.sh"
	pyDockerfile  = "../Dockerfile"
	pyCompose     = "../docker-compose.yml"
	goCompose     = "../docker-compose.go.yml"
	goREADME      = "README.md"
	rootREADME    = "../README.md"
	rootManifest  = "../agentfield-package.yaml"
	pyApp         = "../src/cloudsecurity_af/app.py"
	ciWorkflow    = "../.github/workflows/go.yml"
	workspacesEnv = "SEC_AF_WORKSPACES_DIR"
)

// gateInputsOutsideGo are the files this gate reads that live OUTSIDE go/.
// Each one is a real input: change it and the assertions below change with it.
// They are therefore also inputs to the CI workflow's paths filter — see
// TestPackaging_CIWatchesEveryFileTheGateReads.
var gateInputsOutsideGo = []string{pyDockerfile, pyCompose, goCompose, rootREADME, rootManifest, pyApp}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

// CONTRACT (from src/cloudsecurity_af/app.py:75-93 `_workspaces_root`): the
// explicit SEC_AF_WORKSPACES_DIR branch is taken only when the variable is
// TRUTHY. Otherwise the node mkdir's /workspaces, write-probes it and falls
// back to ~/.sec-af/workspaces on OSError. The Python image and the Python
// compose both leave the variable unset, which is what keeps that fallback
// live — and it has to stay live for the Go node too, because
// docker-compose.go.yml bind-mounts a HOST directory onto /workspaces and a
// bind does not inherit the image's chown, so /workspaces arrives owned by the
// host uid and is unwritable by the image's uid 10001 user.
func TestPackaging_WorkspacesDirIsNotBakedIn(t *testing.T) {
	if strings.Contains(readRepoFile(t, pyDockerfile), workspacesEnv) {
		t.Fatalf("premise broken: the Python Dockerfile now sets %s; re-derive this test", workspacesEnv)
	}
	if strings.Contains(readRepoFile(t, pyCompose), workspacesEnv) {
		t.Fatalf("premise broken: the Python compose now sets %s; re-derive this test", workspacesEnv)
	}

	for _, rel := range []string{goDockerfile, goCompose} {
		for _, line := range strings.Split(readRepoFile(t, rel), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, workspacesEnv+"=") {
				t.Errorf("%s sets %s (%q); that skips app.py's writability probe and 500s every remote repo_url clone under the /workspaces bind",
					rel, workspacesEnv, trimmed)
			}
		}
	}
}

// CONTRACT: the container's working directory must be writable by the runtime
// user. The Python image uses /app, which it chowns and which no compose file
// mounts over. /workspaces is the one directory docker-compose.go.yml replaces
// with a host bind, so it cannot serve as the cwd.
func TestPackaging_WorkdirIsNotTheBindMountedWorkspaces(t *testing.T) {
	body := readRepoFile(t, goDockerfile)
	re := regexp.MustCompile(`(?m)^WORKDIR\s+(\S+)`)
	matches := re.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		t.Fatal("go/Dockerfile declares no WORKDIR")
	}
	last := matches[len(matches)-1][1]
	if last == "/workspaces" {
		t.Errorf("runtime WORKDIR is %s, which docker-compose.go.yml bind-mounts from the host and is therefore not writable by uid 10001", last)
	}
}

// CONTRACT (from src/cloudsecurity_af/config.py:91-96, mirrored in
// internal/config): harness_model resolves CLOUDSECURITY_MODEL first, then
// HARNESS_MODEL, then the default. The entrypoint writes opencode.json's model
// AND its single-entry provider whitelist, and the node passes its own resolved
// model to opencode with -m; if the two use different precedence, opencode is
// invoked with a model its own config does not whitelist — the exact failure
// the script's header says it exists to prevent.
func TestPackaging_EntrypointHonorsTheModelPrecedenceChain(t *testing.T) {
	body := readRepoFile(t, goEntrypoint)
	if !strings.Contains(body, `MODEL="${CLOUDSECURITY_MODEL:-${HARNESS_MODEL:-`) {
		t.Errorf("docker-entrypoint.sh must resolve CLOUDSECURITY_MODEL before HARNESS_MODEL; got:\n%s", body)
	}
	// The image bakes HARNESS_MODEL, so a chain that starts at HARNESS_MODEL
	// can never reach CLOUDSECURITY_MODEL inside the container.
	if !strings.Contains(readRepoFile(t, goDockerfile), "HARNESS_MODEL=") {
		t.Fatal("premise broken: go/Dockerfile no longer bakes HARNESS_MODEL; re-derive this test")
	}
}

// CONTRACT: one stack, one health cadence. The image's own HEALTHCHECK already
// mirrors the Python image (30s/5s/3); a compose healthcheck fully overrides the
// image directive, so it must not drift from it either.
func TestPackaging_HealthcheckCadenceMatchesThePythonStack(t *testing.T) {
	want := map[string]string{
		"interval":     "30s",
		"timeout":      "5s",
		"retries":      "3",
		"start_period": "15s",
	}
	// Derive the expectation from the Python compose rather than hard-coding it.
	pyNode := healthcheckBlock(t, readRepoFile(t, pyCompose), "http://localhost:8005/health")
	for key, value := range want {
		if pyNode[key] != value {
			t.Fatalf("premise broken: the Python node's healthcheck %s is %q, not %q; re-derive this test", key, pyNode[key], value)
		}
	}

	goNode := healthcheckBlock(t, readRepoFile(t, goCompose), "http://localhost:8015/health")
	for key, value := range want {
		if goNode[key] != value {
			t.Errorf("docker-compose.go.yml healthcheck %s = %q, want %q (the Python node's cadence)", key, goNode[key], value)
		}
	}

	image := readRepoFile(t, goDockerfile)
	if !strings.Contains(image, "HEALTHCHECK --interval=30s --timeout=5s --retries=3") {
		t.Error("go/Dockerfile's HEALTHCHECK no longer matches the Python image's 30s/5s/3")
	}
}

// healthcheckBlock returns the key/value pairs of the healthcheck: block whose
// test line contains probe.
func healthcheckBlock(t *testing.T, compose, probe string) map[string]string {
	t.Helper()
	lines := strings.Split(compose, "\n")
	start := -1
	for i, line := range lines {
		if strings.Contains(line, probe) && strings.Contains(line, "test:") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no healthcheck test line containing %q", probe)
	}
	out := map[string]string{}
	for _, line := range lines[start+1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			break
		}
		key = strings.TrimSpace(key)
		if key != "interval" && key != "timeout" && key != "retries" && key != "start_period" {
			break
		}
		out[key] = strings.TrimSpace(value)
	}
	return out
}

// CONTRACT: the root manifest redirects a git install to go/, so the quickstart
// paragraph that describes `af install <repo url>` must not promise a Python
// virtualenv. The redirect is a git-install behaviour only — the local-path
// escape hatch has to be documented where a user first meets the command.
func TestPackaging_RootREADMEQuickstartDescribesTheRedirect(t *testing.T) {
	manifest := readRepoFile(t, rootManifest)
	if !strings.Contains(manifest, "superseded_by:") {
		t.Fatal("premise broken: the root manifest no longer declares superseded_by; re-derive this test")
	}

	readme := readRepoFile(t, rootREADME)
	quickstart := sectionBody(t, readme, "### Install into AgentField (`af install`)")
	if strings.Contains(quickstart, "provisions an isolated Python environment") {
		t.Error("the quickstart still claims `af install <repo url>` provisions a Python venv; the manifest redirect installs the Go package, which is compiled with `go build`")
	}
	for _, want := range []string{
		"follows the repository manifest",
		"replaced in place",
		"node-scoped secrets",
		"af install ./cloudsecurity-af",
	} {
		if !strings.Contains(quickstart, want) {
			t.Errorf("the quickstart does not mention %q", want)
		}
	}
}

// sectionBody returns the markdown between heading and the next heading of the
// same or higher level.
func sectionBody(t *testing.T, doc, heading string) string {
	t.Helper()
	idx := strings.Index(doc, heading)
	if idx < 0 {
		t.Fatalf("README has no %q section", heading)
	}
	rest := doc[idx+len(heading):]
	level := strings.Count(strings.SplitN(heading, " ", 2)[0], "#")
	for i, line := range strings.Split(rest, "\n") {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if h := len(line) - len(strings.TrimLeft(line, "#")); h <= level {
				return rest[:strings.Index(rest, line)]
			}
		}
	}
	return rest
}

// CONTRACT (from src/cloudsecurity_af/app.py:31
// `NODE_ID = os.getenv("NODE_ID", "cloudsecurity")`): BOTH manifests must
// declare the id the process actually registers under.
//
// `af run` reads expectedNodeID from the manifest
// (control-plane/internal/packages/runner.go), polls /health, extracts
// `node_id` (node_identity.go HealthNodeID) and compares with
// NodeIDsEquivalent, which folds only case and `-`↔`_`. The Python SDK's
// /health reports `{"status": "healthy", "node_id": "cloudsecurity", ...}`, so
// a manifest saying `cloudsecurity-af` makes `af run` kill the process with
//
//	port N is answering health checks as "cloudsecurity", not "cloudsecurity-af"
//	— another process is using the port
//
// which is exactly the local-path install the quickstart documents as the way
// to get the Python node. (The Go SDK's /health carries no node_id, so the Go
// package's manifest is never checked — which is why only the root one broke.)
func TestPackaging_ManifestsDeclareTheNodeIDTheProcessRegisters(t *testing.T) {
	app := readRepoFile(t, pyApp)
	m := regexp.MustCompile(`NODE_ID\s*=\s*os\.getenv\("NODE_ID",\s*"([^"]+)"\)`).FindStringSubmatch(app)
	if m == nil {
		t.Fatalf("premise broken: %s no longer defaults NODE_ID with os.getenv; re-derive this test", pyApp)
	}
	want := m[1]

	for _, rel := range []string{rootManifest, "agentfield-package.yaml"} {
		got := manifestNodeID(t, rel)
		if got != want {
			t.Errorf("%s declares node_id %q, but the node registers as %q — `af run` refuses to start it", rel, got, want)
		}
	}
}

// manifestNodeID reads agent_node.node_id out of a package manifest.
func manifestNodeID(t *testing.T, rel string) string {
	t.Helper()
	body := readRepoFile(t, rel)
	idx := strings.Index(body, "\nagent_node:")
	if idx < 0 {
		t.Fatalf("%s has no agent_node block", rel)
	}
	for _, line := range strings.Split(body[idx+1:], "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "agent_node:") {
			break // left the block
		}
		if strings.HasPrefix(trimmed, "node_id:") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "node_id:"))
		}
	}
	t.Fatalf("%s: agent_node block has no node_id", rel)
	return ""
}

// CONTRACT: a gate that never runs is not a gate. Every file this test file
// reads from outside go/ must appear in BOTH of the workflow's paths filters,
// or a PR that changes only that file merges with the Go workflow skipped —
// and the breakage then surfaces as a `premise broken` fatal on the next
// unrelated go/** PR, attributed to the wrong change.
func TestPackaging_CIWatchesEveryFileTheGateReads(t *testing.T) {
	lists := pathsFilters(t, readRepoFile(t, ciWorkflow))
	if len(lists) != 2 {
		t.Fatalf("expected a paths filter on both the push and pull_request triggers, found %d", len(lists))
	}
	for _, input := range gateInputsOutsideGo {
		rel := strings.TrimPrefix(input, "../")
		for i, list := range lists {
			if !pathsFilterCovers(list, rel) {
				t.Errorf("paths filter #%d does not match %q, so a PR touching it skips this gate entirely: %v", i+1, rel, list)
			}
		}
	}
}

// pathsFilters returns every `paths:` list in the workflow, in file order.
func pathsFilters(t *testing.T, workflow string) [][]string {
	t.Helper()
	var out [][]string
	var current []string
	inList := false
	entry := regexp.MustCompile(`^\s+-\s+"([^"]+)"\s*$`)
	for _, line := range strings.Split(workflow, "\n") {
		if strings.TrimSpace(line) == "paths:" {
			if inList {
				out = append(out, current)
			}
			inList, current = true, nil
			continue
		}
		if !inList {
			continue
		}
		if m := entry.FindStringSubmatch(line); m != nil {
			current = append(current, m[1])
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, current)
		inList, current = false, nil
	}
	if inList {
		out = append(out, current)
	}
	return out
}

// pathsFilterCovers reports whether any entry matches rel, honoring the one
// glob form the workflow uses (`prefix/**`).
func pathsFilterCovers(list []string, rel string) bool {
	for _, entry := range list {
		if entry == rel {
			return true
		}
		if strings.HasSuffix(entry, "/**") && strings.HasPrefix(rel, strings.TrimSuffix(entry, "**")) {
			return true
		}
	}
	return false
}

// CONTRACT (from src/cloudsecurity_af/app.py:75-93 `_workspaces_root`): the
// /workspaces bind is NOT automatically a shared checkout.
//
// Both images run as uid 10001 (Dockerfile / go/Dockerfile), a bind does not
// inherit the image's `chown`, and Docker auto-creates the default
// ./workspaces root-owned — so the write probe fails and each node falls back
// to its own container-local ~/.sec-af/workspaces. The compose comment and the
// Go README must not promise one host checkout without that condition; the
// same compose file says so fifteen lines earlier, and a reader who believes
// the unconditional claim will look for clones that are not there.
func TestPackaging_SharedCheckoutClaimIsConditional(t *testing.T) {
	if !strings.Contains(readRepoFile(t, goCompose), workspacesEnv+" is deliberately unset") {
		t.Fatal("premise broken: the compose add-on no longer explains why the write probe must stay live; re-derive this test")
	}
	for _, rel := range []string{goCompose, goREADME} {
		body := readRepoFile(t, rel)
		if strings.Contains(body, "so both nodes resolve a given") {
			t.Errorf("%s still claims unconditionally that both nodes share one host checkout", rel)
		}
		if !strings.Contains(body, "~/.sec-af/workspaces") {
			t.Errorf("%s describes the bind without naming the ~/.sec-af/workspaces fallback the default takes", rel)
		}
	}
}

// CONTRACT (from the control plane): the installed-package REGISTRY is keyed by
// the manifest `name:`, not by `agent_node.node_id`.
//
//	control-plane/internal/packages/git.go:649 and installer.go:1112
//	  registry.Installed[metadata.Name] = InstalledPackage{...}
//	control-plane/internal/core/services/agent_service.go:840-858
//	  findAgentInRegistry normalises only by stripping hyphens
//
// so `cloudsecurity` -> `cloudsecurity` never matches `cloudsecurity-af` ->
// `cloudsecurityaf`, and `af run cloudsecurity` fails with "agent node
// cloudsecurity not installed". Reproduced on a machine with the package
// installed: `/home/…/.agentfield/installed.yaml` is keyed `cloudsecurity-af`.
// `af call` is the opposite — it resolves by NODE ID — which is exactly what
// makes a quickstart that mixes the two look right.
func TestPackaging_AfRunUsesThePackageNameAndAfCallTheNodeID(t *testing.T) {
	pkgName := manifestName(t, rootManifest)
	nodeID := manifestNodeID(t, rootManifest)
	if pkgName == nodeID {
		t.Skip("package name and node id are identical; the confusion this guards cannot arise")
	}

	// Only RUNNABLE lines count — a line whose trimmed form starts with the
	// command. Prose that quotes the wrong form in order to warn about it (as
	// go/README's install block does) must not trip the gate.
	runLine := regexp.MustCompile(`^af run ([A-Za-z0-9._-]+)`)
	callLine := regexp.MustCompile(`^af call ([A-Za-z0-9_-]+)\.`)
	for _, rel := range []string{goREADME, rootREADME} {
		for _, line := range strings.Split(readRepoFile(t, rel), "\n") {
			line = strings.TrimSpace(line)
			if m := runLine.FindStringSubmatch(line); m != nil && m[1] != pkgName {
				t.Errorf("%s documents `af run %s`; the registry is keyed by the manifest name %q, so that is \"not installed\"", rel, m[1], pkgName)
			}
			if m := callLine.FindStringSubmatch(line); m != nil && m[1] != nodeID {
				t.Errorf("%s documents `af call %s.…`; calls resolve by node id %q", rel, m[1], nodeID)
			}
		}
	}
}

// CONTRACT: the Go image must not share a Docker tag with the Python image.
//
// The root README builds the PYTHON image with `-t cloudsecurity-af`, which
// Docker resolves to `cloudsecurity-af:latest`. The two artifacts differ (the
// Python image is PORT=8005 + `python -m cloudsecurity_af.app`, the Go image is
// PORT=8015 + the static binary), so a shared tag means whichever was built
// last silently owns it and `docker run cloudsecurity-af` gets the other node.
func TestPackaging_GoImageTagDoesNotCollideWithThePythonImage(t *testing.T) {
	// Only RUNNABLE lines count, for the same reason as the test above.
	dockerBuild := regexp.MustCompile(`^docker build\b.*-t\s+([A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?)`)
	tagsIn := func(rel string) []string {
		var out []string
		for _, line := range strings.Split(readRepoFile(t, rel), "\n") {
			if m := dockerBuild.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				out = append(out, withLatest(m[1]))
			}
		}
		return out
	}

	pythonTags := map[string]bool{}
	for _, line := range strings.Split(readRepoFile(t, rootREADME), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "go/Dockerfile") {
			continue // a Go build documented in the root README
		}
		if m := dockerBuild.FindStringSubmatch(trimmed); m != nil {
			pythonTags[withLatest(m[1])] = true
		}
	}
	if len(pythonTags) == 0 {
		t.Skip("the root README documents no `docker build -t …` for the Python image")
	}

	makefile := readRepoFile(t, "Makefile")
	m := regexp.MustCompile(`(?m)^IMAGE \?= *(\S+)`).FindStringSubmatch(makefile)
	if m == nil {
		t.Fatal("premise broken: go/Makefile no longer defines IMAGE ?=; re-derive this test")
	}
	goTags := map[string][]string{
		"go/Makefile IMAGE":         {withLatest(m[1])},
		"go/README.md docker build": tagsIn(goREADME),
	}
	for where, tags := range goTags {
		for _, tag := range tags {
			if pythonTags[tag] {
				t.Errorf("%s tags the Go image %q, the same tag the root README builds the PYTHON image with; whichever is built last silently owns it", where, tag)
			}
		}
	}
}

func withLatest(tag string) string {
	if strings.Contains(tag, ":") {
		return tag
	}
	return tag + ":latest"
}

// CONTRACT: go/README's environment table is the node's documented surface, so
// every variable the Go code reads directly must appear in it. XDG_DATA_HOME —
// which the Go image and compose set and the Python ones do not — was the one
// that did not, which is how an ops divergence went unrecorded.
func TestPackaging_READMEDocumentsEveryEnvVarTheNodeReads(t *testing.T) {
	getenv := regexp.MustCompile(`os\.(?:Getenv|LookupEnv)\("([A-Z0-9_]+)"\)`)
	read := map[string]bool{}
	err := filepath.Walk("internal", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			return readErr
		}
		for _, m := range getenv.FindAllStringSubmatch(string(body), -1) {
			read[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/: %v", err)
	}
	if len(read) == 0 {
		t.Fatal("premise broken: no os.Getenv call found under internal/; re-derive this test")
	}

	readme := readRepoFile(t, goREADME)
	for name := range read {
		if !strings.Contains(readme, "`"+name+"`") {
			t.Errorf("go/README.md does not document %s, which internal/ reads", name)
		}
	}
}

// manifestName returns a manifest's top-level `name:`.
func manifestName(t *testing.T, rel string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^name:\s*(\S+)`).FindStringSubmatch(readRepoFile(t, rel))
	if m == nil {
		t.Fatalf("%s has no top-level name:", rel)
	}
	return m[1]
}
