<div align="center">

# CloudSecurity AF

### AI-Native Cloud Infrastructure Security Scanner Built on [AgentField](https://github.com/Agent-Field/agentfield)

[![Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-16a34a?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Built with AgentField](https://img.shields.io/badge/Built%20with-AgentField-0A66C2?style=for-the-badge)](https://github.com/Agent-Field/agentfield)
[![More from Agent-Field](https://img.shields.io/badge/More_from-Agent--Field-111827?style=for-the-badge&logo=github)](https://github.com/Agent-Field)

<p>
  <a href="#what-you-get-back">Output</a> •
  <a href="#why-cloudsecurity">Why CloudSecurity</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="docs/ARCHITECTURE.md">Full Spec</a>
</p>

</div>

Most IaC tools tell you everything that is wrong. CloudSecurity tells you what is most dangerous **first**.

It connects individual misconfigurations into realistic risk chains, validates which ones matter most, and gives teams a clear fix-first path before deployment. Open source, API-first, and designed for fast CI workflows.

<p align="center">
  <img src="assets/hero.png" alt="CloudSecurity AF — shift-left attack path analysis" width="100%" />
</p>

## Why CloudSecurity?

Checkov, tfsec, and KICS are strong at broad control checks. Wiz, Orca, and Prisma Cloud are strong once infrastructure is live. CloudSecurity fills the shift-left gap in between: **priority-grade attack path analysis directly from IaC, before deployment**.

| Capability | CloudSecurity AF | Checkov / tfsec / KICS | Wiz / Orca / Prisma Cloud |
|---|---|---|---|
| **Core value** | Risk-prioritized attack-path triage pre-deploy | Broad policy/rule coverage | Runtime posture and exposure monitoring |
| **Attack path chains** | Yes (CHAIN phase) | No (individual findings) | Yes |
| **Requires deployment** | **No** — IaC only | No — IaC only | **Yes** — live cloud |
| **Decision quality** | Fix-first, exploitability-oriented output | Large findings list, less chain context | Strong runtime context after deploy |
| **Remediation context** | IaC fix path + impact framing | Basic fix hints | Mostly runtime-centric workflows |
| **Cost profile** | **Free / open source** (BYOK model cost) | Free / open source | Enterprise platform contracts ($$$) |

## Where CloudSecurity Sits in the Stack

CloudSecurity is not a replace-all scanner. It is the **decision layer** in a modern cloud security stack:

- **Rule scanners** (Checkov/tfsec/KICS): broad deterministic control coverage.
- **CloudSecurity**: pre-deploy risk prioritization and multi-resource attack-path context.
- **Runtime CNAPP** (Wiz/Orca/Prisma Cloud): deployed-cloud visibility and runtime monitoring.

Recommended operating model:

1. Run rule scanner + CloudSecurity in PR for breadth + fix-first prioritization.
2. Use runtime CNAPP after deploy for drift and production-state risk.

## Architecture

<p align="center">
  <img src="assets/architecture.png" alt="CloudSecurity AF Signal Cascade Pipeline" width="100%" />
</p>

- **RECON**: Reads IaC, builds a resource graph, and optionally pulls live cloud state and drift.
- **HUNT**: Runs 7 parallel domain hunters (IAM, network, data, secrets, compute, logging, compliance).
- **CHAIN**: Combines individual findings into multi-step attack paths across resources.
- **PROVE**: Adversarial verification — tries to disprove each path. Near-zero false positives.
- **REMEDIATE**: Generates IaC fix diffs and evaluates breaking change / downtime impact.

> Full architecture deep-dive: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Quick Start

```bash
pip install cloudsecurity-af

# Start AgentField control plane
# (typically at http://localhost:8080)

cloudsecurity-af  # starts on port 8004

# Trigger a scan
curl -X POST http://localhost:8004/api/v1/execute/async/cloudsecurity.scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/org/infra-repo"}'
```

Key API skills:
- `cloudsecurity.scan` (Tier 1 static analysis)
- `cloudsecurity.prove` (Tier 2+ live verification flow)

## Three Tiers

| Tier | Input | Capability |
|---|---|---|
| **Tier 1 (No Credentials)** | `repo_url` | Static IaC analysis, resource graph construction, attack path discovery, and IaC remediation generation |
| **Tier 2 (Read-Only Credentials)** | `repo_url` + cloud config | Tier 1 plus live verification and drift detection |
| **Tier 3 (Deep Mode)** | Cloud credentials (repo optional) | Tier 2 plus full graph traversal, cross-account analysis, and deeper IAM simulation workflows |

## CI/CD Integration

CloudSecurity is designed for PR-time scanning with SARIF upload:

```yaml
name: cloudsecurity-scan
on:
  pull_request:
    paths:
      - '**/*.tf'
      - '**/*.yaml'
      - '**/*.yml'

jobs:
  infrastructure-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Trigger CloudSecurity
        run: |
          curl -sS -X POST "$AGENTFIELD_SERVER/api/v1/execute/async/cloudsecurity.scan" \
            -H "Content-Type: application/json" \
            -d '{"input":{"repo_url":".","depth":"quick","output_formats":["sarif","json"]}}'
```

See [`docs/GITHUB_ACTIONS.md`](docs/GITHUB_ACTIONS.md) for full Tier 1 and Tier 2 workflows.

## Output Formats

- `sarif`: SARIF 2.1.0 for GitHub code scanning and security platforms
- `json`: Full structured output for pipelines and APIs
- `markdown`: Human-readable report for platform/security reviews

## Configuration

### Key Environment Variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTFIELD_SERVER` | No | `http://localhost:8080` | AgentField control plane URL |
| `NODE_ID` | No | `cloudsecurity` | Agent node identifier |
| `OPENROUTER_API_KEY` | Yes | - | Model provider credential |
| `CLOUDSECURITY_PROVIDER` | No | `opencode` | Harness provider override |
| `CLOUDSECURITY_MODEL` | No | `minimax/minimax-m2.5` | Harness model |
| `CLOUDSECURITY_AI_MODEL` | No | `CLOUDSECURITY_MODEL`/`AI_MODEL` fallback | `.ai()` gate model |
| `CLOUDSECURITY_MAX_TURNS` | No | `50` | Max turns per harness call |
| `CLOUDSECURITY_REPO_PATH` | No | cwd | Local repository path fallback |
| `AGENT_CALLBACK_URL` | No | `http://127.0.0.1:8004` | Agent callback endpoint |

### Core `CloudSecurityInput` Fields

- `repo_url`, `branch`, `commit_sha`, `base_commit_sha`
- `depth` (`quick` | `standard` | `thorough`)
- `severity_threshold` (`critical` | `high` | `medium` | `low` | `info`)
- `output_formats` (`sarif` | `json` | `markdown`)
- `compliance_frameworks` (for example: `cis_aws`, `soc2`, `hipaa`, `pci_dss`)
- `cloud` (`provider`, `regions`, `account_id`, `assume_role_arn`) for Tier 2+
- Budget controls: `max_cost_usd`, `max_duration_seconds`, `max_concurrent_hunters`, `max_concurrent_provers`
- Scope filters: `include_paths`, `exclude_paths`
- CI fields: `is_pr`, `pr_id`, `fail_on_findings`

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

pytest
ruff check src tests
mypy src

# Run service locally
cloudsecurity-af
```

Package metadata:
- Python: `>=3.11`
- License: Apache-2.0
- Core deps: `agentfield`, `pydantic>=2.0`, `pyhcl2>=4.0`

## Open Core Model

CloudSecurity uses an open-core model: `scan` and `prove` remain open source (Apache 2.0), while enterprise adds org-scale controls such as multi-account management, scheduled monitoring, and RBAC/audit features. See [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md) for the full tier breakdown.

## License

CloudSecurity AF is licensed under Apache 2.0. See [`LICENSE`](LICENSE).
