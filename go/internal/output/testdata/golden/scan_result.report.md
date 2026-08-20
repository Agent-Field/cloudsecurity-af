# CloudSecurity AF Infrastructure Security Report

## Summary

- Repository: `https://github.com/Agent-Field/vulnerable-infra`
- Commit: `0f1e2d3c4b5a69788796a5b4c3d2e1f000112233`
- Branch: `main`
- Timestamp: `2026-05-06T07:08:09.123456+00:00`
- Depth profile: `standard`
- Tier: **2** (live)
- Providers: aws, gcp
- Resources scanned: **137**
- Findings: **4** (confirmed: 1, likely: 1, inconclusive: 1, not exploitable: 1)
- Noise reduction: **78.9%**

## Findings

### Wildcard IAM policy on the task role

- ID: `finding-iam-1`
- Verdict: `confirmed` | Severity: `critical`
- Risk score: **9.50/10**
- Category: `overprivilege` | Hunter: `iam`
- Location: `iam.tf:41`
- Description: The task role can perform any action on any resource.
- Attack path: **Public ALB to customer PII bucket**
- Compliance: CIS-AWS-1.16, SOC2-CC6.1
- Remediation: Scope the policy to the two objects the service actually reads.
  - **WARNING: Breaking change**
  - Downtime: seconds

```hcl
resource "aws_iam_role_policy" "app" {
  policy = jsonencode({ Action = "*" })
}
```

### Security group open to the internet

- ID: `finding-net-1`
- Verdict: `likely` | Severity: `high`
- Risk score: **7.25/10**
- Category: `public_exposure` | Hunter: `network`
- Location: `network.tf:12`
- Description: 0.0.0.0/0 on port 443.
- Attack path: **Public ALB to customer PII bucket**
- Drift detected: `aws_s3_bucket.pii` (critical)
- Compliance: CIS-AWS-5.2
- Remediation: Restrict ingress to the corporate CIDR.

### Load balancer logs disabled

- ID: `finding-net-2`
- Verdict: `inconclusive` | Severity: `low`
- Risk score: **2.00/10**
- Category: `public_exposure` | Hunter: `network`
- Location: `network.tf:88`

### Unused KMS key

- ID: `finding-dropped`
- Verdict: `not_exploitable` | Severity: `medium`
- Risk score: **0.00/10**
- Category: `encryption` | Hunter: `data`
- Location: `kms.tf:3`
- Description: The key has no grants.

## Attack Paths

### Public ALB to customer PII bucket

- ID: `path-1`
- Combined severity: `critical`
- Entry: `aws_lb.public` → Target: `aws_s3_bucket.pii`
- Findings involved: `finding-net-1`, `finding-iam-1`
- Steps:
  1. `aws_lb.public` (aws_lb) — Reach the listener from the internet via `ingress 0.0.0.0/0:443`
  2. `aws_iam_role.app` (aws_iam_role) — Assume the task role via `sts:AssumeRole`
  3. `aws_s3_bucket.pii` (aws_s3_bucket) — Read every object via `s3:GetObject`
- Blast radius — data stores: aws_s3_bucket.pii, aws_rds_cluster.main
- Blast radius — compute: aws_ecs_service.api

## Drift Summary

- Drifted resources: **3**
- Shadow IT (cloud-only) resources: **1**

## Compliance

- Frameworks checked: CIS-AWS, SOC2

## Performance & Cost

- Duration: 412.6s
- Agent invocations: 23
- Cost: $1.2346
- Cost breakdown:
  - recon: $0.1346
  - hunt: $0.5000
  - chain: $0.2000
  - prove: $0.4000
