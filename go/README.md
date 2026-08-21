# CloudSecurity AF — Go node

A Go implementation of the CloudSecurity-AF cloud-infrastructure security scanner.
It registers the same reasoner surface under the same names as the Python node,
exposes a byte-compatible HTTP API, and drives the same control-plane DAG, so the
UI renders the identical multi-phase orchestration graph (see
[Pipeline DAG on the control plane](#pipeline-dag-on-the-control-plane)).
The Python package under `src/cloudsecurity_af/` is untouched; this
implementation lives entirely under `go/`.

One binary:

| Binary             | Node ID          | Default port | Role                                    |
|--------------------|------------------|--------------|-----------------------------------------|
| `cloudsecurity-af` | `cloudsecurity`  | `8015`       | Full scan pipeline (`scan` and `prove`) |

Module path: `github.com/Agent-Field/cloudsecurity-af/go`.

> **Node id vs package name.** The package is named `cloudsecurity-af`; the node
> it registers is `cloudsecurity`. That is the Python node's behaviour too
> (`NODE_ID = os.getenv("NODE_ID", "cloudsecurity")` in `app.py`), so calls are
> `cloudsecurity.scan` / `cloudsecurity.prove`. Both manifests — the root one
> and `go/agentfield-package.yaml` — declare `node_id: cloudsecurity`, the id
> the process actually registers; `go/packaging_test.go` fails the build if
> either drifts from `app.py`'s default.
>
> The two names are not interchangeable on the command line: `af run` and
> `af logs` take the PACKAGE name (`cloudsecurity-af`, the registry key), while
> `af call` takes the NODE id (`cloudsecurity.scan`).

## Install

Installing the bare repository URL follows the root manifest's redirect to this
package, so the process you get is the Go node, registered as `cloudsecurity`:

```bash
af install https://github.com/Agent-Field/cloudsecurity-af
af run cloudsecurity-af      # the PACKAGE name — `af run cloudsecurity` is "not installed"
af call cloudsecurity.scan --in '{"repo_url":"https://github.com/org/infra-repo"}'
```

`af run` picks a free port starting at 8001 and exports it as `PORT`, so an
installed node does **not** land on 8015 — pass `--port 8015` if you want it
there. `8015` is the binary's own default (a bare `go run ./cmd/cloudsecurity-af`
or `make run`) and what `docker-compose.go.yml` sets explicitly.

To install the Python node deliberately, clone the repository and run
`af install ./cloudsecurity-af`; local-path installs do not follow the redirect.
`NODE_ID` / `PORT` still override the Go defaults if you want a different
id/port.

## Reasoners

Two externally driven reasoners, exactly as `src/cloudsecurity_af/app.py`:

| Reasoner | Tier | Builds                                                             |
|----------|------|--------------------------------------------------------------------|
| `scan`   | 1    | static IaC scan; `cloud=None`                                       |
| `prove`  | 2    | live scan; `CloudConfig(provider, regions=["us-east-1"], assume_role_arn)` |

Both accept the same pipeline knobs (`depth`, `severity_threshold`,
`output_formats`, `compliance_frameworks`, `max_cost_usd`,
`max_duration_seconds`, `include_paths`, `exclude_paths`, `is_pr`,
`fail_on_findings`). `scan` additionally takes `base_commit_sha`, `pr_id` and
the two concurrency caps; `prove` additionally takes `cloud_provider`,
`cloud_regions` and `assume_role_arn`. The exact parameter list is published to
the control plane as each reasoner's input schema.

Behind them are the 20 router reasoners (tagged `cloud`, `security`,
`infrastructure`): four recon agents, seven hunters, the path constructor, the
two provers, the fix generator, and the five `*_phase` drivers.

## Pipeline DAG on the control plane

A scan is not one execution. `scan`/`prove` build a `ScanOrchestrator`, which
calls the five phase reasoners through the control plane, and each phase calls
its own agents the same way — so the run renders as this graph:

```
scan / prove
├── recon_phase
│   ├── run_iac_reader
│   ├── run_resource_graph_builder          (after iac_reader)
│   ├── run_cloud_connector  ┐ gather (2) — only tier >= 2 with a cloud config
│   └── run_drift_detector   ┘
├── hunt_phase
│   └── run_<hunter>_hunter × 5 (quick) / 7 (standard, thorough)  semaphore max(1,min(3,N))
├── chain_phase
│   └── run_path_constructor
├── prove_phase
│   └── run_static_prover × K (tier < 2) | run_live_prover × K    semaphore 3
└── remediation_phase
    └── run_fix_generator × M
```

Every arrow is an `Agent.Call(ctx, "<NODE_ID>.<reasoner>", kwargs)` with the
same target name and kwargs the Python node uses, so the node/edge multiset is
identical between the two implementations. The handler's `ctx` is threaded
through unchanged — that is what parents the child execution under the `scan`
execution.

## Depending on the AgentField Go SDK

This module depends on the AgentField Go SDK
(`github.com/Agent-Field/agentfield/sdk/go`) via a **real, committed `require`**
resolved from `proxy.golang.org` — there is **no `replace` directive** and no
sibling checkout to lay out. `go build ./...` works out of the box against the
pinned SDK version in `go.mod`.

- **CI / Docker.** `go mod download` pulls the SDK (and every other dependency)
  straight from the module proxy.
- **Dev — optional Go workspace.** A gitignored `go.work` (spanning this module
  and a local `agentfield/sdk/go` checkout) is the way to develop against
  unreleased SDK changes. It is never committed.

The one non-SDK third-party dependency is `github.com/hashicorp/hcl/v2`, which
replaces Python's `pyhcl2` in the deterministic Terraform parser.

## Build & run locally

From `go/`:

```bash
make build          # go build ./...
make vet            # go vet ./...
make test           # go test ./...
make fmt-check      # test -z "$(gofmt -l .)"
make check          # all four — the CI gate
make fmt            # gofmt -w .
make run            # run the node (cloudsecurity, :8015)
```

`make run` needs a control plane reachable at `AGENTFIELD_SERVER` (default
`http://localhost:8080`). The node reads all configuration from the environment
at startup.

## Docker

Multi-stage build: a checksum-verified AForge CLI fetch (the same stage the
Python `Dockerfile` uses), a Go builder, and a slim Debian runtime with the
pinned `opencode` CLI, a non-root `cloudsecurity` user, and the single static
binary at `/usr/local/bin/cloudsecurity-af`. `docker-entrypoint.sh` generates
`opencode.json` at container start from `CLOUDSECURITY_MODEL`, falling back to
`HARNESS_MODEL` and then to the image default — `config.py`'s precedence chain,
so the model env vars are actually honoured (the Python image bakes a fixed
config instead). `CLOUDSECURITY_MODEL` is the one to reach for inside the
image, since the Dockerfile already sets `HARNESS_MODEL`.

The build context is the **repo root** so the `go/` module is in context:

```bash
# from the repo root
docker build -f go/Dockerfile -t cloudsecurity-af-go:latest .
```

The tag is `cloudsecurity-af-go`. The root README's
`docker build ... -t cloudsecurity-af .` builds the **Python** image and
resolves to `cloudsecurity-af:latest`, so sharing the tag would make whichever
image was built last silently own it — and the two differ (port 8005 vs 8015, a
different entrypoint). `make docker-build` and CI use the same `-go` tag.

### Compose: opt-in add-on to the Python stack

`docker-compose.go.yml` (at the repo root) is an **add-on**, not a standalone
stack. It defines only the Go node and joins the Python stack's compose network
as an external reference, sharing the control plane (`agentfield`). The Python
`docker-compose.yml` is left untouched. Start the Python stack first, then layer
the Go node:

```bash
docker compose up -d                          # Python stack (control plane + cloudsecurity-af :8005)
docker compose -f docker-compose.go.yml up -d # adds cloudsecurity-go :8015
```

Adds:

| Service            | Port   | Node id            | Notes              |
|--------------------|--------|--------------------|--------------------|
| `cloudsecurity-go` | `8015` | `cloudsecurity-go` | full scan pipeline |

The workspaces directory is a **host bind mount**, not a named volume — the
Python compose mounts `${SCAN_REPOS_PATH:-./workspaces}` into `/workspaces` and
the add-on mirrors that exact bind (same variable, same default). Both nodes
resolve a given `repo_url` to the same checkout only when that directory is
writable by uid 10001, the user both images run as: with the default
`./workspaces`, Docker auto-creates the bind target owned by the host uid, so
`app.py::_workspaces_root`'s write probe fails and each node falls back to its
own container-local `~/.sec-af/workspaces`. Set `SCAN_REPOS_PATH` to a
directory uid 10001 can write if you want one shared clone.

The control plane (`:8080` inside the network) comes from the Python stack via
the external `cloudsecurity-af_default` network; this assumes the Python stack
was brought up with the default project name `cloudsecurity-af` (its compose
has no explicit `name:`, so the project name is the checkout directory's
basename). See the compose file header for the `COMPOSE_PROJECT_NAME` override.
Health: `curl -f http://localhost:8015/health`.

## Environment variables

The node is configured entirely through the environment.

| Variable                     | Purpose                                                              |
|------------------------------|----------------------------------------------------------------------|
| `OPENROUTER_API_KEY`         | LLM provider key (OpenRouter) — required                             |
| `AGENTFIELD_SERVER`          | Control-plane URL (default `http://localhost:8080`)                  |
| `AGENTFIELD_API_KEY`         | Control-plane API key (if the CP has auth enabled)                   |
| `AGENT_CALLBACK_URL`         | Base URL the CP uses to reach this node; unset → `http://localhost:<PORT>` |
| `NODE_ID`                    | Node ID (default `cloudsecurity`)                                    |
| `PORT`                       | Listen port (default `8015`)                                         |
| `HARNESS_PROVIDER`           | Harness provider (default `aforge`; `opencode` to roll back). `CLOUDSECURITY_PROVIDER` wins over it |
| `AGENTFIELD_AFORGE_COMMAND`  | AForge headless command — `exec` (default) or `do`                   |
| `HARNESS_MODEL`              | Harness model. `CLOUDSECURITY_MODEL` wins over it                    |
| `AI_MODEL`                   | Model for direct `.ai()` calls. `CLOUDSECURITY_AI_MODEL` wins over it |
| `CLOUDSECURITY_MAX_TURNS`    | Harness turn cap (default `50`); a malformed value fails the boot    |
| `CLOUDSECURITY_OPENCODE_BIN` | opencode executable (default `opencode`)                             |
| `CLOUDSECURITY_AFORGE_BIN`   | aforge executable (default `aforge`; `AFORGE_BIN` is the fallback)   |
| `SEC_AF_WORKSPACES_DIR`      | Clone root for remote `repo_url` values (default `/workspaces`, falling back to `~/.sec-af/workspaces`) |
| `CLOUDSECURITY_REPO_PATH`    | Repo path used when `repo_url` is neither a directory nor a URL      |
| `XDG_DATA_HOME`              | Data home forwarded to the harness (default `<tmpdir>/opencode-shared-data`). The Go image and `docker-compose.go.yml` set it to `/home/cloudsecurity/.local/share`, backed by the `opencode-data` volume; the Python image leaves it unset — see divergence 6 |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` / `AWS_REGION` / `AWS_DEFAULT_REGION` | Read-only AWS credentials forwarded to the harness |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCP credentials forwarded to the harness                         |
| `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` / `AZURE_SUBSCRIPTION_ID` | Azure credentials forwarded to the harness |

Note: the code default model is `openrouter/minimax/minimax-m2.5`, while the
Docker image / compose / manifest set
`HARNESS_MODEL=deepseek/deepseek-v4-flash-0731`. The env var always wins; both
defaults are intentional (they mirror the Python node).

## Deliberate divergences from the Python node

Everything else is a 1:1 port (same concurrency bounds, same result key sets,
same error strings, and prompt text that is byte-identical apart from item 7
below). These are on purpose and are commented at the source:

1. **Callback URL.** Python hardcodes the fallback
   `http://host.docker.internal:8020` — a Docker-Desktop-only host name, on the
   wrong port (the node listens on 8005). The Go node leaves `PublicURL` empty
   when `AGENT_CALLBACK_URL` is unset, so the SDK uses
   `http://localhost:<listen port>`, which is correct on bare metal. Every
   container deployment sets `AGENT_CALLBACK_URL` explicitly anyway.
2. **AI config.** The Go SDK's `ai.Config` rejects an empty API key at
   construction, so `AIConfig` is attached only when `OPENROUTER_API_KEY` is
   set; and the `openrouter/` routing prefix is stripped for the direct API call
   (Python's LiteLLM consumes that prefix itself). The harness model keeps the
   prefix.
3. **Failure diagnostics.** Python prints `SCAN ERROR: <exc>` plus a traceback
   before returning 500; Go prints the same line without a traceback (Go error
   values carry no stack).
4. **Number literals lost by the SDK decoder.** The Go SDK decodes a reasoner
   body with a plain `encoding/json` decoder (no `UseNumber`), so every JSON
   number reaches the handler as `float64` and the literal's spelling is gone
   before the port sees it. Two consequences, both narrow: an integral float in
   a free-form `Any` field (`DriftedResource.iac_config`, `ConfigDiff.iac_value`)
   re-renders as `7`, where Python keeps `7.0` (`internal/afx/bind.go`); and a
   number handed to a `str` parameter is rendered with the integer spelling, so
   `{"depth": 4}` gives Python's `"4"` while `{"depth": 4.0}` gives `"4"` where
   Python gives `"4.0"` (`internal/afx/handlerinput.go`). Both trade the rarer
   reading for the common one — the alternative turns every `{"port": 5432}`
   into `5432.0`.
5. **Map key order.** A Go map has no insertion order, so `pyfmt.Dumps` sorts
   keys where a Python dict would keep the order it was built in. The two
   fields whose Python order is fixed and knowable — `by_severity` (the
   `Severity` enum order) and `cost_breakdown` (`_PHASE_ORDER`) — are declared
   in `schemas.BySeverityOrder()` / `schemas.CostBreakdownOrder` and rendered in
   that order by every renderer, including the `scan` / `prove` reply. Only
   `metadata`, whose keys are assembled ad hoc, is still sorted.
6. **`XDG_DATA_HOME` in the image.** The Go `Dockerfile` sets
   `XDG_DATA_HOME=/home/cloudsecurity/.local/share` and
   `docker-compose.go.yml` backs it with the named volume `opencode-data`; the
   Python image and compose set neither, so `provider_env()` falls back to
   `<tmpdir>/opencode-shared-data` — container-local and lost on restart. The
   node CODE is a 1:1 port (`internal/config`'s `ProviderEnv` reads the same
   variable with the same fallback); only the packaging differs, so the harness
   data home survives a container restart on the Go side.
7. **Key order in the harness prompt's JSON Schema block.** Python appends
   `json.dumps(Model.model_json_schema(), indent=2)` to every
   `app.harness(..., schema=Model)` prompt, which preserves pydantic's field
   declaration order. The Go path is a `map[string]any` end to end —
   `harnessx.SchemaFor[T]()` decodes the committed fixture into one and the SDK
   renders it with `json.MarshalIndent`, which sorts map keys — so the block
   carries the same schema with the keys alphabetised. For `HuntResult` that is
   a 199-line diff of identical content at an identical 4174 bytes, so the SDK's
   4000-token large-schema branch takes the same branch on both sides. Only the
   ORDER differs: `harnessx.LoadEmbeddedSchema` decodes with `UseNumber` so
   pydantic's numeric literals (`"default": 0.0`) survive verbatim, and
   `go/scripts/gen_schemas.py` writes the fixtures with `sort_keys=True` so the
   committed file matches the prompt byte for byte (pinned by
   `TestEmbeddedSchemas_AreKeySortedLikeTheSDKWillRenderThem`). The order itself
   is not fixable inside this port — both `agent.Harness` and
   `harness.BuildPromptSuffix` take a `map[string]any`, so an order-preserving
   schema type would have to come from the SDK.
8. **pydantic scalar coercion the SDK harness cannot reproduce.**
   `afx.Bind` ports pydantic v2's lax scalar ladder (`internal/afx/lax.go`), so
   every ported `model_validate` accepts what Python accepts. The Go SDK's
   HARNESS validation does not: it decodes the model reply with a plain
   `json.Unmarshal` AND validates it against the committed pydantic schema, so
   a model that writes `"iac_line": "12"` or `"security_relevant": "true"`
   burns the schema-retry budget and ends as a harness error, where the Python
   node's `schema.model_validate(data)` accepts it on the first attempt.
   Closing this needs a change in `sdk/go/harness`.
9. **Non-finite floats.** Python's `float()` and pydantic both accept `"NaN"`,
   `"Infinity"`, `"-inf"` and the overflowing `"1e999"` for `max_cost_usd`, and
   the scan then runs (every budget comparison against a non-finite number is
   False). JSON has no literal for a non-finite number and `encoding/json`
   refuses to marshal one, so Go rejects those four spellings with the ordinary
   "cannot unmarshal string ... into float64" (`afx.pyFloat`). Any finite
   spelling — including `"2.5"` — is coerced exactly as pydantic does.

## Testing

`go test ./...` covers the port end to end: golden tests compare every prompt
builder byte-for-byte against the Python originals (`scripts/gen_golden.py`
regenerates the fixtures with the Python interpreter), schema fixtures under
`internal/harnessx/testdata/schemas/` are the real `model_json_schema()` output,
the phase tests assert the exact `.call` targets, kwargs and semaphore bounds,
and the node tests pin the 22-reasoner registration surface and the 400/500
error mapping.
