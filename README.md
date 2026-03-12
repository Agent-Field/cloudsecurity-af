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

## One-Call DX

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/cloudsecurity.scan \
  -H "Content-Type: application/json" \
  -d '{"input": {"repo_url": "https://github.com/org/infra-repo"}}'
```

Returns risk-prioritized attack paths — not individual findings, but chains showing how misconfigurations combine into real exploits:

```jsonc
{
  "attack_paths": [
    {
      "severity": "critical",
      "title": "Public S3 → IAM Escalation → RDS Exfiltration",
      "chain": [
        {"step": 1, "resource": "aws_s3_bucket.uploads", "issue": "Public read access enabled"},
        {"step": 2, "resource": "aws_iam_role.lambda_exec", "issue": "Wildcard S3 permissions + RDS access"},
        {"step": 3, "resource": "aws_db_instance.production", "issue": "No VPC restriction, accessible from Lambda"}
      ],
      "impact": "Attacker reads S3 bucket → discovers Lambda credentials → pivots to production database",
      "verdict": "confirmed",
      "remediation": "Restrict S3 ACL, scope IAM policy to specific bucket ARN, add VPC security group to RDS"
    }
  ],
  "summary": {"total_findings": 23, "attack_paths": 4, "critical": 1, "high": 2, "confirmed": 3}
}
```

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
# Clone and start with Docker Compose
git clone https://github.com/Agent-Field/cloudsecurity-af.git
cd cloudsecurity-af

# Set your model provider key
export OPENROUTER_API_KEY=sk-or-...

# Start AgentField control plane + CloudSecurity agent
docker compose -f docker-compose.local.yml up -d

# Trigger a scan via the AgentField REST API
curl -X POST http://localhost:8080/api/v1/execute/async/cloudsecurity.scan \
  -H "Content-Type: application/json" \
  -d '{"input":{"repo_url":"https://github.com/org/infra-repo","depth":"quick"}}'

# Returns: {"execution_id":"exec_...","status":"queued", ...}

# Check scan progress
curl http://localhost:8080/api/v1/executions/exec_...

# Retrieve results when complete
curl http://localhost:8080/api/v1/executions/exec_.../result
```

All interaction happens through the [AgentField](https://github.com/Agent-Field/agentfield) control plane REST API. CloudSecurity registers as an agent node — you never call it directly.

## REST API

CloudSecurity exposes two reasoners through the [AgentField control plane](https://github.com/Agent-Field/agentfield). All requests go to the control plane (default `http://localhost:8080`), which routes execution to the agent.

### Trigger a Scan

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/cloudsecurity.scan \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "repo_url": "https://github.com/org/infra-repo",
      "branch": "main",
      "depth": "quick",
      "severity_threshold": "low",
      "output_formats": ["sarif", "json"]
    }
  }'
```

Response:
```json
{
  "execution_id": "exec_20260312_063521_ik2ghzst",
  "run_id": "run_20260312_063521_f6zfmc7q",
  "status": "queued",
  "target": "cloudsecurity.scan",
  "created_at": "2026-03-12T06:35:21Z"
}
```

### Check Execution Status

```bash
curl http://localhost:8080/api/v1/executions/{execution_id}
```

Returns `queued` → `running` → `completed` (or `failed`).

### Retrieve Results

```bash
curl http://localhost:8080/api/v1/executions/{execution_id}/result
```

<details>
<summary><strong>Tier 2 — Live Verification (with cloud credentials)</strong></summary>

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/cloudsecurity.prove \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "repo_url": "https://github.com/org/infra-repo",
      "cloud_provider": "aws",
      "cloud_regions": ["us-east-1"],
      "assume_role_arn": "arn:aws:iam::123456789012:role/SecurityAuditRole",
      "depth": "standard",
      "severity_threshold": "medium",
      "output_formats": ["sarif", "json"]
    }
  }'
```

Tier 2 runs the full HUNT → CHAIN → PROVE pipeline with read-only cloud credentials for live verification and drift detection.

</details>

<details>
<summary><strong>Full input reference (<code>CloudSecurityInput</code>)</strong></summary>

```json
{
  "input": {
    "repo_url": "https://github.com/org/infra-repo",
    "branch": "main",
    "commit_sha": null,
    "base_commit_sha": null,
    "depth": "quick | standard | thorough",
    "severity_threshold": "critical | high | medium | low | info",
    "output_formats": ["sarif", "json", "markdown"],
    "compliance_frameworks": ["cis_aws", "soc2", "hipaa", "pci_dss"],
    "include_paths": ["modules/networking/"],
    "exclude_paths": ["tests/", ".git/"],
    "is_pr": false,
    "pr_id": null,
    "fail_on_findings": false,
    "max_cost_usd": 5.0,
    "max_duration_seconds": 3600,
    "max_concurrent_hunters": 7,
    "max_concurrent_provers": 3
  }
}
```

For Tier 2+ add `cloud` config:
```json
{
  "input": {
    "repo_url": "...",
    "cloud_provider": "aws",
    "cloud_regions": ["us-east-1", "eu-west-1"],
    "assume_role_arn": "arn:aws:iam::123456789012:role/SecurityAuditRole"
  }
}
```

</details>

<details>
<summary><strong>API endpoints summary</strong></summary>

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/execute/async/cloudsecurity.scan` | Trigger Tier 1 IaC scan (async) |
| `POST` | `/api/v1/execute/async/cloudsecurity.prove` | Trigger Tier 2+ live verification (async) |
| `GET` | `/api/v1/executions/{execution_id}` | Check execution status |
| `GET` | `/api/v1/executions/{execution_id}/result` | Retrieve completed results |
| `GET` | `/api/v1/nodes` | List registered agent nodes |
| `GET` | `/api/v1/health` | Control plane health check |

All endpoints are part of the [AgentField control plane API](https://github.com/Agent-Field/agentfield). See the [AgentField documentation](https://agentfield.dev/docs) for the full API reference.

</details>

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
| `CLOUDSECURITY_MODEL` | No | `openrouter/minimax/minimax-m2.5` | Harness model |
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

# Build and run via Docker
docker compose -f docker-compose.local.yml build
docker compose -f docker-compose.local.yml up -d
```

Package metadata:
- Python: `>=3.11`
- License: Apache-2.0
- Core deps: `agentfield`, `pydantic>=2.0`, `pyhcl2>=2.0`

## Open Core Model

CloudSecurity uses an open-core model: `scan` and `prove` remain open source (Apache 2.0), while enterprise adds org-scale controls such as multi-account management, scheduled monitoring, and RBAC/audit features. See [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md) for the full tier breakdown.

## License

CloudSecurity AF is licensed under Apache 2.0. See [`LICENSE`](LICENSE).
