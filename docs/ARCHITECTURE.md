# CloudSecurity AF Architecture

## Design Philosophy: Harness-First

CloudSecurity AF is an orchestration of autonomous harnesses, not a programmatic scanner with rules. Each harness is a guided LLM agent with full tool access — it can read IaC files, reason about security implications, write code (boto3/gcloud/az scripts), execute that code against live cloud APIs, and interpret results.

**What the orchestrator does (programmatic, thin):**
- Phase pipeline management (RECON → HUNT → CHAIN → PROVE → REMEDIATE)
- Budget enforcement and timeout control
- Parallelism coordination (semaphores, queues)
- Deterministic scoring formula
- Fingerprint-based deduplication
- SARIF/JSON/Markdown output formatting

**What harnesses do (intelligent, thick):**
- Everything else. All reading, reasoning, discovering, verifying, and fix generation.

### Why Harness-First Beats Rules

| Rule-Based Scanner (Checkov, tfsec) | Harness-First (CloudSecurity) |
|---|---|
| Checks one resource at a time against a rule database | Reads infrastructure holistically, reasons about resource *combinations* |
| Can only find what it has rules for | Can find novel misconfigurations it's never seen before |
| Fails silently on unfamiliar IaC patterns | Reasons about unfamiliar patterns, adapts approach |
| Static analysis only | Can write and execute code to verify findings against live cloud |
| Rule maintenance burden grows linearly | Zero rule maintenance — the harness IS the intelligence |

### `.harness()` vs `.ai()` Decision Map

| Role | Primitive | Why |
|---|---|---|
| IaC reader / resource graph builder | `.harness()` | Navigates multi-file Terraform, follows module references, multi-turn |
| Cloud connector (queries AWS/GCP/Azure) | `.harness()` | Writes and executes boto3/gcloud scripts, interprets output, multi-turn |
| Each hunter (IAM, network, data, etc.) | `.harness()` | Reads resource configs, reasons about security, follows references |
| Attack path constructor | `.harness()` | Meta-prompting: examines findings, crafts child harness prompts |
| Each prover (static, live, drift) | `.harness()` | Writes verification scripts, executes them, weighs evidence |
| Fix generator | `.harness()` | Reads current IaC, writes patches, reasons about breaking changes |
| Strategy selection gate | `.ai()` | Flat routing decision: which hunters to activate based on recon summary |
| Finding deduplication (semantic) | `.ai()` | Binary classification: are these two findings the same? |
| Severity classification gate | `.ai()` | Flat enum output from small context |
| Drift significance gate | `.ai()` | Binary: is this drift security-relevant or cosmetic? |

---

## Progressive Tiers

CloudSecurity operates in three tiers based on what credentials are available. The architecture is the same — tiers unlock additional harnesses.

| Tier | Input | Unlocked Harnesses | CI/CD | Typical Cost | Time |
|---|---|---|---|---|---|
| **1: Static** | `repo_url` only | IaC reader, all hunters, static prover, fix generator | ✅ Every PR | ~$0.10–0.50 | 30–90s |
| **2: Live** | `repo_url` + cloud credentials | + Cloud connector, drift detector, live prover, blast radius | ✅ With secrets | ~$0.30–1.50 | 2–5 min |
| **3: Deep** | Cloud credentials (repo optional) | + Full resource graph traversal, cross-account paths, IAM simulator | Scheduled/on-demand | ~$1.00–5.00 | 5–15 min |

---

## Signal Cascade Pipeline

```
RECON ──→ HUNT ──→ CHAIN ──→ PROVE ──→ REMEDIATE
  │         │        │         │          │
  │         │        │         │          └─ IaC Fix Generator
  │         │        │         │             Breaking Change Analyzer
  │         │        │         │
  │         │        │         ├─ Static Prover (Tier 1)
  │         │        │         ├─ Live Prover (Tier 2+)
  │         │        │         ├─ Drift Prover (Tier 2+)
  │         │        │         └─ Blast Radius Calculator (Tier 2+)
  │         │        │
  │         │        └─ Attack Path Constructor (meta-prompting)
  │         │           Spawns child harnesses per discovered path
  │         │
  │         ├─ IAM Hunter
  │         ├─ Network Hunter
  │         ├─ Data Hunter
  │         ├─ Secrets Hunter
  │         ├─ Compute Hunter
  │         ├─ Logging Hunter
  │         └─ Compliance Hunter
  │
  ├─ IaC Reader (Tier 1)
  ├─ Resource Graph Builder (Tier 1)
  ├─ Cloud Connector (Tier 2+)
  └─ Drift Detector (Tier 2+)
```

Each phase narrows the signal:
- RECON: Understand the infrastructure
- HUNT: Find individual misconfigurations (parallel, semaphore-bounded)
- CHAIN: Combine findings into multi-resource attack paths
- PROVE: Adversarial verification — try to disprove each path
- REMEDIATE: Generate IaC fix diffs for confirmed/likely findings

---

## Phase 1: RECON

### Purpose
Build a complete understanding of the infrastructure being analyzed. Output is a resource graph with relationships, plus (Tier 2+) live cloud state and drift information.

### Harnesses

#### `iac_reader` (.harness)
**Goal**: Read all IaC files and produce a structured resource inventory.

The harness navigates the repository, reading `.tf`, `.json` (CloudFormation), `.yaml` (K8s), and module references. It follows Terraform module sources, resolves variable references, and understands resource dependencies.

**Key capability**: The harness can handle arbitrary IaC patterns — custom modules, complex expressions, `for_each` / `count`, data sources, dynamic blocks — because it reads and reasons rather than parsing against a fixed grammar.

**Output schema**:
```python
class ResourceInventory(BaseModel):
    resources: list[Resource]
    modules: list[Module]
    variables: list[Variable]
    outputs: list[Output]
    provider_configs: list[ProviderConfig]
    iac_type: str  # terraform | cloudformation | kubernetes
    iac_version: str | None
```

```python
class Resource(BaseModel):
    id: str                        # e.g., "aws_s3_bucket.data_lake"
    type: str                      # e.g., "aws_s3_bucket"
    name: str                      # e.g., "data_lake"
    provider: str                  # aws | gcp | azure
    file_path: str
    line_number: int
    config: dict[str, Any]         # raw resource configuration
    references: list[str]          # IDs of resources this depends on
    referenced_by: list[str]       # IDs of resources that depend on this
```

#### `resource_graph_builder` (.harness)
**Goal**: From the resource inventory, reason about implicit relationships and produce a connected graph.

**Why harness, not code**: Many resource relationships are *implicit*. A Lambda and an S3 bucket in the same module probably interact. An IAM role referenced in an `assume_role_policy` creates a trust relationship. A security group attached to an EC2 instance creates a network boundary. The harness reasons about these connections rather than matching patterns.

**Output schema**:
```python
class ResourceGraph(BaseModel):
    nodes: list[ResourceNode]
    edges: list[ResourceEdge]
    clusters: list[ResourceCluster]  # logical groupings (VPC, subnet, module)

class ResourceEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str  # "references" | "trust" | "network_path" | "data_access" | "execution"
    description: str
```

#### `cloud_connector` (.harness, Tier 2+)
**Goal**: Query live cloud APIs to build a snapshot of actual deployed state.

**Key capability**: The harness writes and executes its own boto3/gcloud/az CLI scripts. It adapts to what it discovers — if it finds an S3 bucket, it checks the ACL; if it finds an IAM role, it checks the attached policies; if it finds an EC2 instance, it checks its security groups and metadata service version.

**Output**: Same `ResourceInventory` schema but populated from live API calls instead of IaC files.

#### `drift_detector` (.harness, Tier 2+)
**Goal**: Compare IaC-declared state against live cloud state. Identify meaningful security drift.

**Key capability**: The harness examines both the IaC resource graph and the live resource graph, then reasons about which differences are security-relevant vs cosmetic. "Tag change" = cosmetic. "Security group rule added" = security-relevant.

**Output schema**:
```python
class DriftReport(BaseModel):
    drifted_resources: list[DriftedResource]
    iac_only_resources: list[str]     # declared in IaC but not deployed
    cloud_only_resources: list[str]    # deployed but not in IaC (shadow IT)

class DriftedResource(BaseModel):
    resource_id: str
    resource_type: str
    iac_config: dict[str, Any]
    live_config: dict[str, Any]
    diffs: list[ConfigDiff]
    security_relevant: bool
    significance: str  # critical | high | medium | low

class ConfigDiff(BaseModel):
    attribute: str
    iac_value: Any
    live_value: Any
    security_impact: str | None
```

### RECON Orchestration

```python
# Tier 1: Static only
iac_inventory = await app.call("cloudsecurity.run_iac_reader", repo_path=repo_path)
resource_graph = await app.call("cloudsecurity.run_resource_graph_builder",
    resources=iac_inventory)

# Tier 2+: Add live cloud
if cloud_config:
    live_inventory = await app.call("cloudsecurity.run_cloud_connector",
        cloud_config=cloud_config)
    drift_report = await app.call("cloudsecurity.run_drift_detector",
        iac_graph=resource_graph, live_inventory=live_inventory)
```

---

## Phase 2: HUNT

### Purpose
Find individual misconfigurations and policy violations. Each hunter is a specialized harness that focuses on one security domain.

### Parallelism
Hunters run in parallel with semaphore-bounded concurrency (default: 4 concurrent). Each hunter receives the resource graph from RECON and produces findings relevant to its domain.

### Strategy Selection Gate (.ai)
Before launching hunters, an `.ai()` gate examines the RECON output and selects which hunters to activate:
- AWS resources detected → activate IAM, Network, Data, Compute hunters
- Kubernetes manifests detected → activate K8s-specific sub-hunters
- No encryption configs found → prioritize Data hunter
- No logging configs found → prioritize Logging hunter

### Hunters

#### `iam_hunter` (.harness)
**Scope**: IAM policies, roles, users, groups, trust relationships, cross-account access.

**What it reasons about**:
- Wildcard permissions (`"Action": "*"`, `"Resource": "*"`)
- Overprivileged roles (Lambda with `s3:*` when it only needs `s3:GetObject` on one bucket)
- Trust relationships (who can assume this role? Is it too broad?)
- Cross-account access patterns
- Missing MFA requirements
- Root account usage
- Service-linked roles with excessive permissions

**Key harness capability**: Can write and execute IAM policy simulator queries (Tier 2+) to determine *effective* permissions, not just *declared* permissions.

#### `network_hunter` (.harness)
**Scope**: Security groups, NACLs, route tables, VPC peering, public subnets, load balancers.

**What it reasons about**:
- Overly permissive ingress rules (`0.0.0.0/0` on sensitive ports)
- Missing egress restrictions
- Public subnet placement of sensitive resources
- VPC peering with overly broad routing
- Load balancer security (HTTP without redirect, missing WAF)
- Network path from internet to internal resources

#### `data_hunter` (.harness)
**Scope**: Storage encryption, access controls, backup policies, data classification.

**What it reasons about**:
- Unencrypted storage (S3, RDS, EBS, DynamoDB)
- Public bucket policies / ACLs
- Missing versioning and backup
- Cross-region replication without encryption
- Data lifecycle policies (or lack thereof)
- Sensitive data exposure (bucket names suggesting PII, credentials, backups)

#### `secrets_hunter` (.harness)
**Scope**: Hardcoded credentials, key management, secret rotation.

**What it reasons about**:
- Hardcoded AWS keys, database passwords, API tokens in IaC
- Missing KMS encryption for secrets
- Secrets Manager / Parameter Store usage (or lack thereof)
- Key rotation policies
- Default passwords on managed resources

#### `compute_hunter` (.harness)
**Scope**: EC2, Lambda, ECS, EKS instance configurations.

**What it reasons about**:
- IMDSv1 enabled (credential theft risk)
- Outdated AMIs / runtimes
- Missing patching / auto-update policies
- Privileged containers
- Host networking mode
- Missing resource limits (CPU/memory → DoS risk)

#### `logging_hunter` (.harness)
**Scope**: CloudTrail, VPC Flow Logs, GuardDuty, CloudWatch, access logging.

**What it reasons about**:
- Missing or disabled CloudTrail
- Missing VPC Flow Logs on production VPCs
- GuardDuty not enabled
- S3 access logging disabled on sensitive buckets
- Missing alarm configurations for security events
- Log encryption and retention policies

#### `compliance_hunter` (.harness)
**Scope**: Framework-specific control checking (CIS AWS, SOC2, HIPAA, PCI-DSS).

**What it reasons about**:
- Given a specific framework (e.g., CIS AWS Benchmark 3.0), systematically checks each control
- Maps infrastructure state to control requirements
- Identifies gaps with specific control IDs
- The harness READS the compliance framework requirements and reasons about whether the infrastructure meets them — it doesn't check against a rule database

### Hunt Output Schema
```python
class RawFinding(BaseModel):
    id: str
    hunter_strategy: str             # iam | network | data | secrets | compute | logging | compliance
    title: str
    description: str
    category: str                    # overprivilege | public_exposure | missing_encryption | ...
    resources: list[AffectedResource]
    estimated_severity: Severity
    confidence: Confidence
    iac_file: str
    iac_line: int
    config_snippet: str
    benchmark_id: str | None         # CIS control ID, SOC2 control, etc.
    fingerprint: str

class AffectedResource(BaseModel):
    resource_id: str
    resource_type: str
    attribute: str                   # the specific attribute that's misconfigured
    current_value: str
    recommended_value: str
```

### Hunt Orchestration (Streaming)
```python
findings_queue: asyncio.Queue[list[RawFinding]] = asyncio.Queue()
semaphore = asyncio.Semaphore(max_concurrent_hunters)

async def _run_and_enqueue(hunter_name: str) -> None:
    async with semaphore:
        raw = await app.call(f"cloudsecurity.run_{hunter_name}_hunter",
            repo_path=repo_path, resource_graph=resource_graph, depth=depth)
        await findings_queue.put(raw.findings)

# Producers (parallel) + Consumer (incremental dedup)
producers = [asyncio.create_task(_run_and_enqueue(h)) for h in active_hunters]
consumer = asyncio.create_task(_incremental_dedup())
await asyncio.gather(*producers)
deduped_findings = await consumer
```

---

## Phase 3: CHAIN (The Differentiator)

### Purpose
This is what makes CloudSecurity fundamentally different from rule-based scanners and from SEC-AF. The CHAIN phase examines individual findings from HUNT and constructs **multi-resource attack paths** — sequences of misconfigurations that, when combined, create exploitable paths through the infrastructure.

### Why This Requires Meta-Prompting
A rule-based scanner can flag "S3 bucket is public" and "Lambda has s3:* permissions" separately. But the dangerous insight is that these two findings, when combined with "the Lambda is triggered by a public API Gateway," create a data exfiltration path. Discovering these combinations requires reasoning about the resource graph — which is exactly what a harness excels at.

### `path_constructor` (.harness, meta-prompting)

The path constructor harness receives:
1. All findings from HUNT
2. The resource graph from RECON
3. (Tier 2+) Drift report and live state

It reasons about which findings **connect** through the resource graph, then for each potential attack path, **spawns a child harness** to trace the path in detail.

**Parent harness behavior**:
1. Reads all findings and the resource graph
2. Identifies clusters of findings that share resource connections
3. For each cluster, crafts a specific investigation prompt for a child harness
4. Collects child results and assembles complete attack paths

**Child harness prompt (crafted at runtime by parent)**:
```
You are tracing a potential attack path through cloud infrastructure.

Starting point: {finding_A.resource} ({finding_A.description})
Connected resource: {edge.description}
End point: {finding_B.resource} ({finding_B.description})

Resource graph context:
{relevant_subgraph}

Determine:
1. Can an attacker actually traverse from the starting point to the end point?
2. What intermediate resources are involved?
3. What is the blast radius if this path is exploited?
4. What data or systems are ultimately reachable?

If the path is viable, describe each step with the specific resource and permission that enables it.
```

**Output schema**:
```python
class AttackPath(BaseModel):
    id: str
    title: str
    description: str
    steps: list[AttackStep]
    entry_point: str                # public-facing resource where attack begins
    target: str                     # what the attacker ultimately reaches
    findings_involved: list[str]    # IDs of HUNT findings that compose this path
    combined_severity: Severity
    blast_radius: BlastRadius

class AttackStep(BaseModel):
    step_number: int
    resource_id: str
    resource_type: str
    action: str                     # what the attacker does at this step
    permission_used: str            # the specific permission that enables this step
    description: str

class BlastRadius(BaseModel):
    data_stores_reachable: list[str]
    compute_reachable: list[str]
    estimated_data_volume: str | None
    services_affected: list[str]
```

---

## Phase 4: PROVE

### Purpose
Adversarial verification. For each attack path from CHAIN (and high-severity individual findings), the PROVE phase tries to **disprove** exploitability. This is the same adversarial tension pattern from SEC-AF, adapted for cloud infrastructure.

### Provers

#### `static_prover` (.harness, Tier 1)
**Goal**: Using only the IaC configuration, determine if the attack path is actually traversable.

**What it checks**:
- Are the permissions in the path actually granted? (IAM policy evaluation)
- Is the network path actually open? (Security group + route table + NACL analysis)
- Are there mitigating controls the hunters missed? (SCPs, permission boundaries, conditions)
- Does the resource configuration actually allow the claimed action?

**Key harness capability**: Can write and execute Python code to simulate IAM policy evaluation locally — parsing policy JSON, evaluating conditions, checking for explicit denies.

#### `live_prover` (.harness, Tier 2+)
**Goal**: Verify each step of the attack path against the actual cloud environment.

**What it does**:
- Writes boto3/gcloud/az scripts for each step of the attack path
- Executes them with read-only credentials
- Interprets the results
- Examples:
  - `aws s3api get-bucket-acl` → confirms public access
  - `aws iam simulate-principal-policy` → confirms effective permissions
  - `aws ec2 describe-security-groups` → confirms port is actually open
  - `aws s3 ls s3://bucket/ --summarize` → confirms data exists and estimates volume

#### `drift_prover` (.harness, Tier 2+)
**Goal**: For drift-related findings, prove whether the drift creates an exploitable condition.

**What it checks**:
- Is the drifted configuration less secure than the IaC-declared state?
- Does the drift create a new attack path that doesn't exist in the IaC?
- Is the drift intentional (tagged, documented) or accidental?

#### `blast_radius_calculator` (.harness, Tier 2+)
**Goal**: For confirmed attack paths, calculate the full blast radius.

**What it does**:
- Traces outward from the attack target through the resource graph
- Identifies all data stores, compute resources, and services reachable
- Estimates data volume (Tier 2+: actual `aws s3 ls --summarize`)
- Identifies cross-account impact

### Verdict Model
```python
class Verdict(str, Enum):
    CONFIRMED = "confirmed"          # attack path verified with evidence
    LIKELY = "likely"                 # strong indicators, partial verification
    INCONCLUSIVE = "inconclusive"    # insufficient evidence
    NOT_EXPLOITABLE = "not_exploitable"  # mitigating controls found

class VerifiedFinding(BaseModel):
    id: str
    title: str
    verdict: Verdict
    severity: Severity
    category: str
    resources: list[AffectedResource]
    attack_path: AttackPath | None
    drift: DriftedResource | None
    proof: Proof
    compliance_mappings: list[str]
    risk_score: float                # deterministic formula
    remediation: RemediationSuggestion | None

class Proof(BaseModel):
    method: str  # static_analysis | live_api_verification | iam_simulation | drift_comparison
    evidence: list[str]
    scripts_executed: list[str]      # actual commands/scripts the harness ran
    verification_tier: str           # static | live
```

---

## Phase 5: REMEDIATE

### Purpose
Generate actionable IaC fix diffs for confirmed and likely findings.

### Harnesses

#### `fix_generator` (.harness)
**Goal**: Read the current IaC configuration and write a patch that fixes the finding.

**Key harness capabilities**:
- Reads the actual Terraform/CloudFormation/K8s file
- Understands the context (what else is in the file, what depends on this resource)
- Writes a minimal, correct patch
- Considers side effects (will restricting this security group break the application?)

**Output schema**:
```python
class RemediationSuggestion(BaseModel):
    finding_id: str
    description: str
    diffs: list[IaCDiff]
    breaking_change: bool
    downtime_estimate: str | None    # "none" | "seconds" | "minutes" | "requires_maintenance_window"
    effort: str                      # trivial | moderate | significant
    alternative_approaches: list[str]

class IaCDiff(BaseModel):
    file_path: str
    original_lines: str
    patched_lines: str
    start_line: int
    end_line: int
```

#### `breaking_change_analyzer` (.harness)
**Goal**: For each fix, determine if applying it would cause downtime, data loss, or service disruption.

**What it reasons about**:
- Will changing this security group drop existing connections?
- Will encrypting this S3 bucket require re-uploading all objects?
- Will restricting this IAM role break running services?
- Does this change require a Terraform `destroy` and `create` (vs `update`)?

---

## Scoring Formula (Deterministic)

The risk score is computed programmatically — the harness provides the inputs, the formula is transparent and reproducible.

```python
SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}

EVIDENCE_MULTIPLIERS = {
    "live_verified": 1.0,          # proved against live cloud API
    "iam_simulated": 0.9,          # IAM policy simulation confirms
    "drift_confirmed": 0.85,       # drift detected and verified
    "static_graph_confirmed": 0.7, # resource graph analysis confirms path
    "static_config_match": 0.5,    # individual resource config looks wrong
    "heuristic_match": 0.2,        # pattern-based, not verified
}

EXPOSURE_MULTIPLIERS = {
    "internet_facing": 1.0,
    "vpc_internal": 0.7,
    "private_subnet": 0.5,
    "requires_iam_auth": 0.4,
    "requires_admin": 0.2,
}

def compute_risk_score(finding: VerifiedFinding) -> float:
    severity = SEVERITY_WEIGHTS[finding.severity.value]
    evidence = EVIDENCE_MULTIPLIERS[finding.proof.method]
    exposure = EXPOSURE_MULTIPLIERS.get(finding.exposure, 0.5)
    path_bonus = 2.0 if finding.attack_path else 1.0
    drift_bonus = 1.3 if finding.drift else 1.0

    score = severity * evidence * exposure * path_bonus * drift_bonus
    return round(min(max(score, 0.0), 10.0), 2)
```

---

## Inter-Agent Data Flow

Following the archei rules from `multi-reasoner-archei-rules.md`:

| Edge | Format | Why |
|---|---|---|
| Orchestrator → Hunter (context routing) | **String** | Hunter harness reasons over natural language description of infrastructure |
| Hunter → Deduplicator | **Structured JSON** | Fingerprint comparison is programmatic |
| RECON → HUNT (resource graph) | **Hybrid** | Resource IDs for programmatic routing + descriptions for harness reasoning |
| HUNT → CHAIN (findings) | **String** | Path constructor harness reasons over finding descriptions to identify combinations |
| CHAIN → PROVE (attack paths) | **Hybrid** | Path steps as structured data + narrative context for prover reasoning |
| PROVE → REMEDIATE (verified findings) | **Hybrid** | Verdict/severity as JSON + proof narrative for fix generator reasoning |
| REMEDIATE → Output | **Structured JSON** | SARIF generation is programmatic |

---

## Budget Controls

```python
class BudgetConfig(BaseModel):
    max_cost_usd: float | None = None
    max_duration_seconds: int | None = None
    max_concurrent_hunters: int = 4
    max_concurrent_provers: int = 3
    max_concurrent_chain_children: int = 3
    recon_budget_pct: float = 0.10
    hunt_budget_pct: float = 0.35
    chain_budget_pct: float = 0.20
    prove_budget_pct: float = 0.25
    remediate_budget_pct: float = 0.10
```

---

## Depth Profiles

| Profile | Hunters | Chain Depth | Verification | Typical Time | Typical Cost |
|---|---|---|---|---|---|
| `quick` | 4 core (IAM, network, data, secrets) | Top 5 paths only | Static only | 30–90s | ~$0.10–0.50 |
| `standard` | 7 hunters (core + compute, logging, compliance) | Top 15 paths | Static + live (Tier 2) | 2–5 min | ~$0.30–1.50 |
| `thorough` | All hunters + framework-specific | All viable paths | Full verification | 5–15 min | ~$1.00–5.00 |

---

## Output Formats

| Format | Consumer | Description |
|---|---|---|
| `sarif` | GitHub Code Scanning, security tooling | SARIF 2.1.0 with resource locations mapped to IaC file/line |
| `json` | Pipelines, APIs | Full structured result with verdicts, attack paths, proofs, drift |
| `markdown` | Security teams | Narrative report with executive summary, findings, remediation |

---

## Skills

### `cloudsecurity.scan` (Tier 1)
Static IaC analysis with resource graph reasoning. No cloud credentials needed.

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/cloudsecurity.scan \
  -d '{"input": {"repo_url": "https://github.com/org/infrastructure"}}'
```

### `cloudsecurity.prove` (Tier 2+)
Everything in scan + live cloud verification + drift detection + attack path validation.

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/cloudsecurity.prove \
  -d '{"input": {
    "repo_url": "https://github.com/org/infrastructure",
    "cloud": {"provider": "aws", "regions": ["us-east-1"]}
  }}'
```

Cloud credentials are read from environment variables (AWS_ACCESS_KEY_ID, etc.), never from the API payload.

---

## Comparison: SEC-AF vs CloudSecurity AF

| | SEC-AF | CloudSecurity AF |
|---|---|---|
| **Domain** | Application source code | Cloud infrastructure (IaC + live cloud) |
| **What it reads** | Python, JS, Go, etc. | Terraform, CloudFormation, Kubernetes YAML |
| **What it traces** | Data flow through code (source → sink) | Resource relationships through infrastructure (SG → EC2 → IAM → S3) |
| **What it finds** | Code vulnerabilities (SQLi, XSS, RCE) | Infrastructure misconfigurations + attack paths |
| **How it proves** | Taint analysis + sanitization check | Resource graph traversal + live cloud API verification |
| **Unique capability** | Adversarial HUNT→PROVE on code | CHAIN phase: multi-resource attack path construction (meta-prompting) |
| **Fix output** | Code patches | IaC diffs (Terraform/CloudFormation patches) |
| **Live verification** | No (SAST only) | Yes (Tier 2+: writes and executes boto3/gcloud scripts) |
