package recon

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/prompts"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// warnOut is where the fallback warnings that Python emits with
// `log.warning(...)` are written — i.e. stderr. It is a variable only so tests
// can capture the bytes; production code must never reassign it.
//
// The exact bytes of a Python logging line depend on the process-wide logging
// configuration and are not part of the parity contract (they are human-facing
// diagnostics, like harnessx's stdout blocks). The message TEXT is verbatim.
var warnOut io.Writer = os.Stderr

func logWarning(logger, format string, args ...any) {
	_, _ = fmt.Fprintf(warnOut, "WARNING:%s:%s\n", logger, fmt.Sprintf(format, args...))
}

// iacReaderPromptPath is PROMPT_PATH in iac_reader.py, resolved against the
// embedded prompt tree instead of the installed package's prompts/ directory.
const iacReaderPromptPath = "recon/iac_reader.txt"

// iacReaderTempPrefix is the tempfile.mkdtemp prefix in run_iac_reader.
const iacReaderTempPrefix = "cloudsecurity-recon-iac-reader-"

// RunIaCReader ports run_iac_reader in
// src/cloudsecurity_af/agents/recon/iac_reader.py:
//
//	work_dir = tempfile.mkdtemp(prefix="cloudsecurity-recon-iac-reader-")
//	try:
//	    return _fast_parse(repo_path, work_dir)
//	except Exception as exc:
//	    log.warning("Deterministic parser failed (%s), falling back to harness", exc)
//	    return await _harness_fallback(app, repo_path, work_dir)
//
// PYTHON PARITY — THE WORK DIRECTORY IS NOT CLEANED UP. iac_reader.py imports
// `shutil` and never calls it: unlike cloud_connector/drift_detector there is no
// `finally: shutil.rmtree(...)`, and there cannot be, because the returned
// ResourceInventory.inventory_saved_path points INTO work_dir and every
// downstream phase (the graph builder, the hunters' graph context, the
// orchestrator's provider detection) reads that file. Go therefore does NOT
// defer os.RemoveAll here. The directory is an OS temp dir and is reclaimed with
// the rest of /tmp.
func RunIaCReader(ctx context.Context, app appx.Harnesser, repoPath string) (schemas.ResourceInventory, error) {
	workDir, err := os.MkdirTemp("", iacReaderTempPrefix)
	if err != nil {
		// Python parity: mkdtemp is OUTSIDE the try, so a failure here
		// propagates instead of falling back to the harness.
		return schemas.ResourceInventory{}, fmt.Errorf("cloudsecurity recon: creating iac-reader work dir: %w", err)
	}

	inventory, fastErr := iacFastParseFn(repoPath, workDir)
	if fastErr == nil {
		return inventory, nil
	}
	logWarning("cloudsecurity_af.agents.recon.iac_reader",
		"Deterministic parser failed (%v), falling back to harness", fastErr)
	return iacHarnessFallback(ctx, app, repoPath, workDir)
}

// iacFastParseFn is the fast path RunIaCReader tries first. It is a variable
// ONLY so the test suite can exercise the harness-fallback branch: with the
// real implementation the branch is unreachable from a test, because
// ParseTerraformDirectory fails only on filesystem errors inside a temp
// directory the function itself just created. Production code must never
// reassign it.
var iacFastParseFn = iacFastParse

// iacFastParse ports _fast_parse.
func iacFastParse(repoPath, workDir string) (schemas.ResourceInventory, error) {
	invPath, total, iacType, err := ParseTerraformDirectory(repoPath, workDir)
	if err != nil {
		return schemas.ResourceInventory{}, err
	}
	return schemas.ResourceInventory{
		InventorySavedPath: invPath,
		TotalResources:     total,
		IaCType:            iacType,
		// Python parity: ResourceInventory(...) leaves iac_version at its
		// default of None.
		IaCVersion: nil,
	}, nil
}

// iacHarnessFallback ports _harness_fallback.
func iacHarnessFallback(ctx context.Context, app appx.Harnesser, repoPath, workDir string) (schemas.ResourceInventory, error) {
	prompt, err := BuildIaCReaderPrompt(repoPath)
	if err != nil {
		return schemas.ResourceInventory{}, err
	}
	return harnessx.RunExtract[schemas.ResourceInventory](
		ctx, app, prompt,
		harness.Options{Cwd: workDir, ProjectDir: repoPath},
		"IaC reader",
	)
}

// BuildIaCReaderPrompt renders the IaC reader harness prompt. Exported for the
// golden test, which compares it byte-for-byte against the string the Python
// builder emits.
func BuildIaCReaderPrompt(repoPath string) (string, error) {
	template, err := prompts.Load(iacReaderPromptPath)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(template, "{{REPO_PATH}}", repoPath), nil
}
