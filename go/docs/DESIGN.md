# CloudSecurity-AF Go port — design contract

This document is the design contract the Go port under `go/` is written
against: parity rules, package layout, SDK mapping, DAG shape, packaging and the
testing contract. It mirrors the established Agent-Field porting pattern (pr-af
PRs #53/#54/#64, SWE-AF `go/`), adapted to the fact that this node builds its
reasoner DAG with `app.call(f"{NODE_ID}.<reasoner>")` through the control
plane.

Reference material (read-only):

- pr-af Go port — <https://github.com/Agent-Field/pr-af> under `go/`
  (afx.Bind/ToMap, harnessx.Run[T] with embedded pydantic schemas, node/ wiring,
  register.go, Dockerfile/Makefile/compose, go/README.md, root README section)
- SWE-AF Go port — <https://github.com/Agent-Field/SWE-AF> under `go/`
  (app.Call DAG, envelope.UnwrapCallResult)
- AgentField Go SDK (v0.1.131 is the pinned tag) —
  <https://github.com/Agent-Field/agentfield> under `sdk/go`
  (`agent/agent.go` Call/CallLocal/AI/Note, `agent/harness.go`, `agent/router.go`,
  `harness/provider.go` Options, `harness/result.go`, `ai/request.go` WithSchema)
- AgentField Python SDK (to check what Python does) — the same repository under
  `sdk/python/agentfield`

The Python node this port reproduces lives in this repository:
`src/cloudsecurity_af` (sources) and `tests/` (its test suite).

## -1. Tooling facts

- The generators (`go/scripts/gen_schemas.py`, `go/scripts/gen_golden.py`) need
  a Python 3.11 interpreter with pydantic v2, `agentfield` and this repo's own
  dependencies — the interpreter `af install` provisions for the Python node is
  the convenient one. Run them as
  `PYTHONPATH=<repo>/src <python> go/scripts/gen_schemas.py`. (A system
  `python3` older than 3.11, or one without the deps, will not do.)
- Go toolchain: go1.25 or newer on PATH; the module targets the Go 1.21 language
  level. `GOFLAGS=-mod=mod` is NOT needed; `go mod tidy` resolves
  `github.com/Agent-Field/agentfield/sdk/go v0.1.131` from the proxy.
- Never register a test node against a control plane you do not own: bring up an
  isolated one (see §6).

## 0. Non-negotiables

1. **Python is byte-untouched.** Every diff lives under `go/`, plus
   `docker-compose.go.yml`, the root `agentfield-package.yaml` redirect, one
   root-README section, and `.github/workflows/go.yml`. Never edit `src/`,
   `tests/`, `pyproject.toml`, `Dockerfile`, `docker-compose.yml`.
2. **1:1 parity is the goal.** Same reasoner names, same input parameter
   names/defaults, same result JSON key sets (snake_case, pydantic
   `model_dump()` shape), same prompts (byte-verbatim), same concurrency
   shape (gather/semaphore), same notes (message + tags), same error mapping.
   When Python does something odd, reproduce it and leave a comment
   `// Python parity: ...`. Do not "improve" behavior. If a Python behavior is
   non-deterministic (set iteration order) make it deterministic and comment it.
3. **Same DAG.** Every place Python does `router.call(f"{NODE_ID}.x", ...)` /
   `app.call(...)`, Go does `app.Call(ctx, nodeID+".x", kwargsMap)` with the
   SAME target name and the SAME kwargs keys. Never replace a Python `.call`
   with a direct Go function call — that collapses the control-plane DAG.
   Conversely never add a `.Call` where Python calls a function in-process.
4. **Gate: `cd go && go build ./... && go vet ./... && go test ./... && test -z "$(gofmt -l .)"`**
   must be green for everything you touch. Tests are derived from the Python
   tests and from the behaviors in this doc (validation contract), not from
   the Go implementation.
5. Go 1.21 language level in `go.mod` (`go 1.21`), matching the SDK. Local
   toolchain is go1.25 — fine, but do not use APIs newer than 1.21 (no
   `slices`/`maps` std packages? — those ARE 1.21, ok; `min`/`max` builtins
   are 1.21, ok; avoid `range over int` (1.22) and `iter` (1.23)).
6. No new third-party dependencies beyond: the SDK, `golang.org/x/sync`,
   `github.com/invopop/jsonschema`, `github.com/santhosh-tekuri/jsonschema/v5`
   (pulled by SDK), and for cloudsecurity-af only `github.com/hashicorp/hcl/v2`
   (Terraform parsing, replaces pyhcl2). Ask before adding anything else.

## 1. Repository layout (`go/` at the repo root)

```
go/
├── agentfield-package.yaml   # name = cloudsecurity-af (the product name), language: go
├── Dockerfile                # multi-stage, aforge fetch + opencode, non-root user, static binary
├── docker-entrypoint.sh      # writes opencode.json from HARNESS_MODEL at container start
├── Makefile                  # build/vet/test/check/fmt/run/docker-*
├── README.md                 # build/run/compose/install story (model on pr-af go/README.md)
├── .gitignore                # bin/, go.work*, coverage
├── doc.go                    # package doc for the module root
├── go.mod / go.sum           # module github.com/Agent-Field/cloudsecurity-af/go ; go 1.21 ; sdk/go v0.1.131
├── cmd/cloudsecurity-af/main.go
├── docs/DESIGN.md            # this document
├── scripts/gen_schemas.py    # pydantic model_json_schema() → internal/harnessx/testdata/schemas/*.json
├── scripts/gen_golden.py     # (where useful) Python prompt-builder goldens → internal/.../testdata/*.txt
├── internal/
│   ├── afx/        Bind[T], ToMap, Unwrap/AsMap (the _unwrap/_as_dict parity), DropNulls (model_dump(exclude_none=True))
│   ├── pyfmt/      Round(x, ndigits) banker's rounding (Python round()), Repr(v) Python repr for list/dict/str/bool/None
│   │               (needed wherever a prompt f-string embeds a Python list/dict), FormatFloat (Python str(float))
│   ├── appx/       App interface {Harness, AI, Note, Call} that *agent.Agent satisfies; fakes for tests
│   ├── config/     DepthProfile, BudgetConfig, <Audit|Scan>Config, AIIntegrationConfig (env), ProviderEnv()
│   ├── schemas/    every pydantic model → Go struct (json tags = pydantic field names), enums → string types
│   ├── harnessx/   Run[T] + RegisterSchema + embedded pydantic schema fixtures; Extract (extract_harness_result parity)
│   ├── aix/        Structured[T]: Python `.ai(user=, schema=Model)` = app.AI(WithSystem?, WithSchema(strictified pydantic schema)) → parse T
│   ├── prompts/    embedded copies of the Python prompt .txt files + Load(relpath) + drift test vs the Python tree
│   ├── <domain pkgs>  see §3
│   ├── reasoners/  Name* constants + RegisterAll (router with the Python AgentRouter tags) + handler adapters
│   ├── phases/     the *_phase reasoners (Call-based DAG)
│   ├── orch/       orchestrator (generate_output, checkpoints, budget/cost bookkeeping, progress notes)
│   └── node/       BuildAgent (env → agent.Config), top-level reasoner handlers (scan + prove), Serve
└── test/functional/   (build tag `functional`) registration parity against a live control plane
```

Root additions: `docker-compose.go.yml` (Go node as add-on to the Python
stack, distinct NODE_ID `cloudsecurity-go` and port), root
`agentfield-package.yaml` gains the
`superseded_by: https://github.com/Agent-Field/cloudsecurity-af//go` block
(copy the comment block from pr-af's root manifest verbatim, adjusting names),
root README gains a "Go implementation" section, `.github/workflows/go.yml`
(build/vet/test/gofmt on push + PR, paths-filtered to `go/**`).

Node identity / ports:

| Python code default NODE_ID | Go default NODE_ID | Python port | Go default port | router tags |
|---|---|---|---|---|
| `cloudsecurity` | `cloudsecurity` | 8005 | **8015** | `["cloud","security","infrastructure"]` |

`NODE_ID` and `PORT` env override both (Python parity). `docker-compose.go.yml`
sets `NODE_ID=<name>-go` so both stacks can share one control plane.

## 2. SDK mapping (Python → Go)

| Python (agentfield py SDK) | Go (sdk/go v0.1.131) |
|---|---|
| `Agent(node_id, version, description, agentfield_server, callback_url, api_key, harness_config=HarnessConfig(provider, model, max_turns, env, opencode_bin, aforge_bin, permission_mode="auto"), ai_config=AIConfig(model, api_key, api_base))` | `agent.New(agent.Config{NodeID, Version:"0.1.0", AgentFieldURL, Token, ListenAddress:":"+port, PublicURL: AGENT_CALLBACK_URL, CLIConfig:&agent.CLIConfig{AppDescription}, HarnessConfig:&agent.HarnessConfig{Provider, Model, MaxTurns, PermissionMode:"auto", Env: ProviderEnv(), BinPath: <aforge_bin if provider==aforge, opencode_bin if opencode, else "">}, AIConfig: &ai.Config{Model: strip "openrouter/" prefix, APIKey, BaseURL:"https://openrouter.ai/api/v1"} ONLY when the key is non-empty})` — copy pr-af `node.BuildAgent` incl. the `aiModelForAPI` prefix-strip rationale. cloudsecurity's Python `AIConfig(provider=..., model=...)` has no api_base → Go uses the same OpenRouter BaseURL when OPENROUTER_API_KEY is set (it is the only key the nodes document). |
| `@app.reasoner()` (top-level) | `app.RegisterReasoner(name, handler, agent.WithInputSchema(raw))` — transcribe the Python signature into the input schema (see pr-af `reviewInputSchema`). |
| `router = AgentRouter(tags=[...])`, `@router.reasoner()`, `app.include_router(router)` | `r := agent.NewRouter(); r.RegisterReasoner(name, h)`; `app.IncludeRouter(r, agent.RouterOptions{Tags: tags})` (no Prefix). |
| `await router.call(f"{NODE_ID}.x", a=1, b=2)` | `app.Call(ctx, nodeID+".x", map[string]any{"a":1,"b":2})` — returns the reasoner's result map already unwrapped on success; error on failure. Keep `afx.Unwrap(raw, name)` that mirrors `_unwrap` (error dict → error; `"output"` / `"result"` keys → inner) and `afx.AsMap` (`_as_dict`) for parity; apply them to the returned map exactly where Python does. The ctx passed MUST be the handler's ctx (carries the execution context so the CP parents the child execution). |
| `await app.harness(prompt=p, schema=Model, cwd=c, project_dir=d)` | `harnessx.Run[Model](ctx, app, p, harness.Options{Cwd:c, ProjectDir:d})` — provider/model/max_turns/env/permission come from the agent default HarnessConfig (the Go SDK merges them). `chain_builder` calls harness with NO schema (`app.harness(prompt, cwd=repo_path)`) → `app.Harness(ctx, prompt, nil, nil, opts)` and read `Result.Result` text. |
| `extract_harness_result(result, Model, name)` | `harnessx.Extract[Model](res, name)`: IsError → print the same diagnostic line and return `fmt.Errorf("%s harness error: %s", name, res.ErrorMessage)`; Parsed → value; else TypeError-equivalent error `"%s did not return a valid %s"`. |
| `await app.ai(user=prompt, schema=Model)` / `router.ai(system=, user=, schema=)` | `aix.Structured[Model](ctx, app, system, user)` → `app.AI(ctx, user, ai.WithSystem(system) if system!="", ai.WithSchema(json.RawMessage(strictified schema)))` then `resp.JSON(&v)`. Strictify exactly like Python's `_strictify_openai_schema` (every object: `additionalProperties:false`, `required` = all property names, recursing into `$defs`/`properties`/`items`/`anyOf`). |
| `app.note(msg, tags=[...])` / `router.note(...)` | `app.Note(ctx, msg, tags...)` — same message string, same tag order. |
| `HTTPException(400, detail={"error": msg})` | `return nil, &agent.ExecuteError{StatusCode: 400, Message: msg}` |
| `HTTPException(500, detail={"error": "scan execution failed: ..."})` | `&agent.ExecuteError{StatusCode: 500, Message: "scan execution failed: "+err.Error()}` — app.py raises this one WITHOUT a note; do not add one. |
| `asyncio.gather(*coros)` | `errgroup` / WaitGroup writing into a pre-indexed slice (order preserved). `return_exceptions=True` → per-index error slots. |
| `asyncio.Semaphore(n)` | `semaphore.NewWeighted(n)` from x/sync (or a buffered chan). |
| `asyncio.Queue` producer/consumer (hunt incremental dedup) | channel + consumer goroutine; preserve the note strings. |
| `model_dump()` | `json.Marshal(struct)` — all fields emitted, no `omitempty` (except where Python has `exclude_none=True`: use `afx.DropNulls` on the marshaled map). |
| `Model.model_validate(d)` / `Model(**d)` | `afx.Bind[Model](d)` (JSON round-trip; UnmarshalJSON seeds defaults). |
| `str(float)` in prompts | `pyfmt.FormatFloat` ; `round(x, n)` → `pyfmt.Round` (half-even, like pr-af's). |
| `datetime.now(UTC)` inside `model_dump()` (serialized by FastAPI `jsonable_encoder` → `datetime.isoformat()`) | VERIFIED: `2026-01-02T03:04:05.123456+00:00` (microseconds omitted when zero: `2026-01-02T03:04:05+00:00`). Implement `schemas.Timestamp` (time.Time wrapper) whose MarshalJSON emits exactly that; UnmarshalJSON accepts RFC3339 with or without fraction and `Z`. |

Python round-trips every reasoner boundary through JSON (`model_dump()` →
control plane → `model_validate`). Go must tolerate the same inputs: numbers
arrive as float64 in `map[string]any`; `afx.Bind` handles that.

## 2b. Shared test fake and Python-JSON parity helper

- `internal/appx.Fake` (already written) is THE test double for every package:
  scripted `HarnessFn`/`AIFn`/`CallFn` (helpers `appx.HarnessJSON`, `appx.AIJSON`),
  recorded `Harnesses`/`AIs`/`Notes`/`Calls`, and `MaxConcurrentHarness()` /
  `MaxConcurrentCalls()` for semaphore assertions. Do not write another fake.
- `pyfmt.Dumps(v any, indent int) string` reproduces Python `json.dumps(x, indent=n)`
  applied to a pydantic `model_dump()` dict: walks Go values by reflection
  (struct fields in declaration order honoring json tags, pointers, slices,
  maps with SORTED keys — documented deviation, Python keeps insertion order —
  float64 kinds rendered as Python float repr e.g. `1.0`, ints as ints,
  `true/false/null`, strings escaped like Python's `ensure_ascii=True` (non-ASCII
  → `\uXXXX`, and NO escaping of `<>&`), values implementing json.Marshaler
  (e.g. `schemas.Timestamp`) rendered via their MarshalJSON. `pyfmt.Dumps(v, 0)`
  /`DumpsCompact` = `json.dumps(x)` with `", "` and `": "` separators. Use it
  wherever Python embeds `json.dumps(...)` output in a prompt, a checkpoint file,
  or an output artifact that a test compares textually.

## 2c. Foundation API facts (as actually landed — read the code, these are pointers)
- `harnessx.Run[T](ctx, app, prompt, opts) (*T, *harness.Result, error)`,
  `harnessx.Extract[T](res *harness.Result, dest *T, agentName string) (T, error)`,
  `harnessx.RunExtract[T](ctx, app appx.Harnesser, prompt string, opts harness.Options, agentName string) (T, error)`
  (the 3-arg Extract is deliberate: the Go SDK stores the dest pointer in Result.Parsed),
  `harnessx.SchemaFor[T]() map[string]any` (fixture by Go type name, invopop fallback).
- `aix.Structured[T](ctx, app appx.AIer, system, user string) (T, error)`, `aix.Strictify`.
- `afx.Bind[T]`, `afx.ToMap`, `afx.Unwrap(raw any, name string) (any, error)`, `afx.AsMap(payload any, name string) (map[string]any, error)`, `afx.DropNulls(any) any`.
  This port additionally has `afx.UnwrapStrict` (the phases.py/orchestrator.py variant that also fails on `error_message`/`status in (failed,error)`) — EVERY ported `app.Call` site uses `UnwrapStrict` — and `afx.DumpExcludeNone`.
- `pyfmt.Round(x, ndigits)`, `pyfmt.FormatFloat`, `pyfmt.Str`, `pyfmt.Repr` (maps sorted; use `pyfmt.Ordered`/`pyfmt.O(...)` for insertion-ordered dict repr), `pyfmt.KV`. `pyfmt.Dumps` does NOT exist yet (wave-2 owners S7 / C6 add `pyfmt/pyjson.go`).
- `prompts.Load(rel) (string, error)`, `prompts.MustLoad(rel)`, `prompts.Names()`; files under `internal/prompts/files/<same relative layout as src/<pkg>/prompts>`.
- `config`: `ParseDepth`/`NormalizeDepth`, `DepthHunterMap`/`DepthChainLimits`/`DepthProverCaps`, `BudgetConfig`, `ScanConfigFromInput(scanInput any, repoPath) (ScanConfig, error)` (errors on unknown depth → HTTP 400 path), `NewScanConfigFromView`, `AIConfigFromEnv`, `ProviderEnv` (the node must fail boot on a ProviderEnv error, like Python).
- `schemas`: struct per pydantic class, `New<Model>()` constructors (these mint uuid4 ids; `UnmarshalJSON` seeds defaults but never mints ids), `Timestamp` (+ `ISOFormat()`), enums as string types with `Parse*`/`Valid` (STRICT: unknown/null → unmarshal error, matching pydantic). `PathInvestigationPlan`/`ChildInvestigation` live in `schemas` (do not redeclare in agents/chain); `schemas` imports `scoring` (Severity/EvidenceMethod/Exposure live in scoring), never the reverse; `CloudSecurityInput.Tier()` method. Every ported model declares `PydanticModel()` in `schemas/model.go`, which is what makes `afx.Bind` apply pydantic's lax scalar coercion and its rejection of a null for a non-Optional field.
- Stale Python tests discovered (port the CODE behavior, note the stale assertion): `tests/test_config.py::test_prover_caps` (quick cap is 20), `tests/test_schemas.py` (imports removed ResourceNode/ResourceEdge/ResourceCluster), `tests/test_graph_context.py` + `tests/test_utils.py::TestPromptTemplatesExist` (stale paths/signatures — `build_graph_context_for_hunter(graph_path, inventory_path, domain_keywords)` reads JSON files and returns `(node_lines, inventory_stats, edge_lines)`).
- Live verification (see §6) drives the node with a mock `opencode` shim that resolves every prompt role; the DAG this node produces is fully deterministic under it.

## 3. Port map (Python module → Go package)

| Python | Go package | Notes |
|---|---|---|
| `app.py` | `internal/node` (+ `cmd/cloudsecurity-af`) | two top-level reasoners `scan` and `prove` building `CloudSecurityInput` (scan: `cloud=None`; prove: `CloudConfig(provider, regions default ["us-east-1"], assume_role_arn)`), defaults exclude_paths `["tests/",".git/","examples/",".terraform/"]`; `_workspaces_root()` (`SEC_AF_WORKSPACES_DIR`, `/workspaces` writability probe, `~/.sec-af/workspaces` fallback), `_resolve_repo` (`CLOUDSECURITY_REPO_PATH` fallback), `_run_pipeline` → `ScanOrchestrator.run()`, error mapping `{"error": ...}` 400/500 (`"scan execution failed: "` prefix, no note in Python here — do not add one). Python callback_url default `http://host.docker.internal:8020` — Go: `AGENT_CALLBACK_URL` → PublicURL, else SDK default; comment the difference. |
| `orchestrator.py` | `internal/orch` | `ScanOrchestrator.run()` is THE DAG driver: 5 sequential `app.call`s (`recon_phase`, `hunt_phase`, `chain_phase`, `prove_phase`, `remediation_phase`) with exactly these kwargs, checkpoints, `_emit_progress` (ScanProgress built but NOT emitted as a note in Python — keep it a no-op builder, comment), `agent_invocations = total_selected + len(strategies_run) + 5`, `_generate_output` (threshold filter, `apply_benchmark_severity_floor(first compliance mapping)`, `compute_risk_score(..., Exposure.VPC_INTERNAL, has_attack_path, has_drift)`, counts, drift/shadow-it counts, `CloudSecurityScanResult`, `generate_sarif`). `_PhaseHarnessProxy` is defined but unused by `run()` — port minimal. |
| `reasoners/*.py` + `phases.py` | `internal/reasoners`, `internal/phases` | Register these router reasoners (tags `cloud, security, infrastructure`): `run_iac_reader, run_resource_graph_builder, run_cloud_connector, run_drift_detector, run_iam_hunter, run_network_hunter, run_data_hunter, run_secrets_hunter, run_compute_hunter, run_logging_hunter, run_compliance_hunter, run_path_constructor, run_static_prover, run_live_prover, run_fix_generator, recon_phase, hunt_phase, chain_phase, prove_phase, remediation_phase` (20) + top-level `scan`, `prove` (22 total). `recon_phase`: iac_reader → graph_builder (sequential), then if `tier>=2 && cloud_config != nil` gather(cloud_connector, drift_detector); providers from inventory.json. `hunt_phase`: `DEPTH_HUNTER_MAP` hunters, semaphore, incremental fingerprint dedup then `_cross_hunter_dedup` (first-seen order of the dict; keep highest severity). `chain_phase`: one call to `run_path_constructor` with `max_paths = DEPTH_CHAIN_LIMITS`. `prove_phase`: prioritize by severity, cap `DEPTH_PROVER_CAPS`, semaphore, `run_static_prover` (tier<2) or `run_live_prover`, `attack_path` kwarg only when the finding is in a path; `_fallback_verified` with `drop_reason="prover_error"`; `exclude_none=True` outputs. `remediation_phase` → `run_fix_generator`. `_unwrap` here ALSO treats `error_message`/`status in (failed,error)` as failures — port this stricter variant. |
| `config.py` | `internal/config` | env names `CLOUDSECURITY_PROVIDER`/`HARNESS_PROVIDER` (aforge), `CLOUDSECURITY_MODEL`/`HARNESS_MODEL` (`openrouter/minimax/minimax-m2.5`), `CLOUDSECURITY_AI_MODEL`/`AI_MODEL`/`CLOUDSECURITY_MODEL`, `CLOUDSECURITY_MAX_TURNS` 50, `CLOUDSECURITY_OPENCODE_BIN`, `CLOUDSECURITY_AFORGE_BIN`/`AFORGE_BIN`; `provider_env()` with the AWS/GCP/Azure keys + `AGENTFIELD_AFORGE_COMMAND` + `XDG_DATA_HOME`; `DEPTH_HUNTER_MAP`, `DEPTH_CHAIN_LIMITS`, `DEPTH_PROVER_CAPS`, `BudgetConfig` pcts, `ScanConfig.from_input` (tier from input). `tests/test_config.py`. |
| `schemas/*.py` | `internal/schemas` | input (CloudSecurityInput incl. `tier` logic — read it), recon (ResourceInventory, ResourceGraph, DriftReport, ReconResult, ...), hunt, chain (AttackPath, ChainResult), prove (Proof, ProofMethod, VerifiedFinding, RemediationSuggestion), output (CloudSecurityScanResult, ScanProgress), views. `tests/test_schemas.py`, `test_graph_context.py`. |
| `scoring.py` | `internal/scoring` | Severity, EvidenceMethod, Exposure, `compute_risk_score`, `apply_benchmark_severity_floor`; `tests/test_scoring.py`. |
| `agents/_utils.py` | `internal/harnessx` (+ `internal/agents/util` for the non-harness helpers in that file — read it, it is 175 lines) | `tests/test_utils.py`. |
| `agents/recon/_terraform_parser.py` | `internal/agents/recon/tfparse.go` | Use `github.com/hashicorp/hcl/v2` + `hclsyntax` to parse every `*.tf` (sorted rglob, relative paths); produce the SAME inventory.json shape (`resources[] {id,type,name,provider,file_path,line_number:0,config,references,referenced_by}`, `variables[]`, `outputs[]`, `providers[]`, `modules[]`), `_provider_from_type` map, `_extract_references` regex + `_NON_REF_PREFIXES`, `_sanitize`, reverse references, `json.dump(indent=2, default=str)` → MarshalIndent. Expression → value: literals evaluate (`expr.Value(nil)` for constant exprs → Go scalars/lists/maps), anything non-constant → its source text (Python stringifies non-literal expressions; match as closely as reasonable and document differences). Nested blocks: labeled → `result[sub_name][label] = dict`, unlabeled repeated → list. Test against `tests/fixtures/vulnerable_infra/main.tf` and assert the counts/ids the Python tests assert. |
| `agents/recon/_graph_builder_fast.py`, `resource_graph_builder.py`, `iac_reader.py`, `cloud_connector.py`, `drift_detector.py` | `internal/agents/recon` | fast deterministic paths first, harness fallback on error (same prompts, `{{REPO_PATH}}`-style template substitution). |
| `agents/hunt/*` (7 hunters) | `internal/agents/hunt` | read each; shared prompt assembly helpers in `_utils.py`. |
| `agents/chain/path_constructor.py`, `agents/prove/{static,live}_prover.py`, `agents/remediate/fix_generator.py` | `internal/agents/chain`, `internal/agents/prove`, `internal/agents/remediate` | |
| `output/{sarif,json_output,report}.py` | `internal/output` | |
| `prompts/**` (repo-root `prompts/` AND check if the package bundles them — PR #5 "bundle prompts in the package": find the runtime PROMPT_PATH) | `internal/prompts/files/**` | same embed + drift test approach. |

### The DAG the control plane must show

```
scan / prove
├── recon_phase
│   ├── run_iac_reader
│   ├── run_resource_graph_builder          (after iac_reader)
│   ├── run_cloud_connector  ┐ gather (2) — only tier>=2 with cloud_config (prove reasoner)
│   └── run_drift_detector   ┘
├── hunt_phase
│   └── run_<hunter>_hunter × 5 (quick) / 7 (standard, thorough)   semaphore max(1,min(3,N))
├── chain_phase
│   └── run_path_constructor
├── prove_phase
│   └── run_static_prover × K (tier<2) | run_live_prover × K      semaphore 3
└── remediation_phase
    └── run_fix_generator × M
```

## 4. Testing contract

- Port EVERY Python test file to a Go test in the owning package (same
  assertions, same fixtures). Name tests after the Python ones so reviewers
  can diff coverage (`TestScoring_...` ↔ `test_scoring.py::test_...`).
- Add golden tests for every prompt-building function whose output reaches
  the LLM (`scripts/gen_golden.py` runs the Python builders with fixed inputs
  and writes `testdata/golden/*.txt`; the Go test renders the same inputs and
  compares byte-for-byte). Commit the generator AND the goldens.
- Schema fixtures: `scripts/gen_schemas.py` imports the pydantic models and
  writes `model_json_schema()` JSON for every model that is passed to
  `app.harness(schema=)` or `app.ai(schema=)`. Commit them under
  `internal/harnessx/testdata/schemas/`. Add the pr-af drift test that checks
  every embedded schema's `properties` keys ⊆ the Go struct's json tags and
  vice-versa (required ones).
- Concurrency tests for each phase: a fake `appx.App` whose `Call` records
  (target, kwargs) — assert the exact target names, kwargs keys, call counts,
  order where Python orders, and the max observed concurrency ≤ the semaphore
  limit.
- Node tests: registration parity (exact ordered name list + tags), `scan` /
  `prove` input binding defaults, error mapping.
- Functional test (build tag) against a live CP is optional; the manual live
  verification (§6) is mandatory and done by the integrator.

## 5. Packaging

Copy pr-af's `go/Dockerfile`, `go/docker-entrypoint.sh`, `go/Makefile`,
`docker-compose.go.yml`, `go/README.md`, root README section, root manifest
redirect, and adapt: binary name, user (`cloudsecurity`), ports, env var names
(`HARNESS_PROVIDER`, `HARNESS_MODEL`, `AI_MODEL`, `CLOUDSECURITY_*`,
`SEC_AF_WORKSPACES_DIR`), the aforge fetch stage (take it from the repo's OWN
Python Dockerfile — it is already the checksum-verified download), the Python
image's opencode config (the Go entrypoint generates it from
`CLOUDSECURITY_MODEL`, falling back to `HARNESS_MODEL` — the same precedence
chain `config.py` uses). The Go manifest's
`user_environment` block = the root manifest's block (same keys) — the Go node
reads the same env vars. `go.mod` requires
`github.com/Agent-Field/agentfield/sdk/go v0.1.131` (no replace).
CI: `.github/workflows/go.yml` — `actions/setup-go` with `go-version-file:
go/go.mod`, `working-directory: go`, steps `go build ./...`, `go vet ./...`,
`go test ./...`, `test -z "$(gofmt -l .)"`, `docker build -f go/Dockerfile .`.

## 6. Live verification (integrator)

1. Isolated control plane (the `af` binary, or a fresh build) on a free port
   with `HOME` + `AGENTFIELD_HOME` pointed at a scratch dir — never a control
   plane you do not own.
2. Python node (the installed package, or `pip install -e .` in a venv) and Go
   node (`go run ./cmd/cloudsecurity-af`) both registered (distinct NODE_IDs),
   same `OPENROUTER_API_KEY`, same harness provider/model, same
   `SEC_AF_WORKSPACES_DIR`.
3. Deterministic DAG comparison: a mock harness CLI (`HARNESS_PROVIDER=opencode`
   + `CLOUDSECURITY_OPENCODE_BIN` pointing at a shim that recognizes the
   prompt's role and writes canned schema-valid JSON to the output file; see
   pr-af `go/test/mockcli`) → run `scan` on the same fixture repo through both
   nodes → pull `/api/v1/executions?...`/workflow tree for each run and compare
   the node/edge multiset (parent→child reasoner names, counts). Must be
   identical.
4. Real run (depth `quick`) of the Go node on a small public vulnerable repo
   with the real key → succeeds, result JSON has the expected keys, DAG shape
   matches the Python structure.
