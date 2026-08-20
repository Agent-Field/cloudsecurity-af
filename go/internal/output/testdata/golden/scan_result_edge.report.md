# CloudSecurity AF Infrastructure Security Report

## Summary

- Repository: `repo/with spaces & <brackets>`
- Commit: ``
- Branch: n/a
- Timestamp: `2026-05-06T07:08:09.500000+05:30`
- Depth profile: `thorough`
- Tier: **7** (deep)
- Providers: azure
- Resources scanned: **0**
- Findings: **3** (confirmed: 2, likely: 1, inconclusive: 0, not exploitable: 1)
- Noise reduction: **0.1%**

## Findings

### Unnamed rule

- ID: `finding-fallback`
- Verdict: `confirmed` | Severity: `info`
- Risk score: **0.00/10**
- Category: `` | Hunter: ``
- Location: `:0`

### Unnamed rule, second sighting

- ID: `finding-fallback-2`
- Verdict: `not_exploitable` | Severity: `critical`
- Risk score: **-0.00/10**
- Category: `` | Hunter: ``
- Location: `:0`

### S3 bucket "public" — 世界 🚀

- ID: `finding-éscaped`
- Verdict: `likely` | Severity: `medium`
- Risk score: **2.67/10**
- Category: `public_exposure` | Hunter: `data`
- Location: `s3\buckets.tf:7`
- Description: Bucket ACL is public-read.	See <docs>.
- Compliance: CIS-AWS-2.1.1, §5.2
- Remediation: Set `acl = "private"`.
  - **WARNING: Breaking change**

```hcl
resource "aws_s3_bucket" "b" {
	acl = "public-read"
}
```

## Attack Paths

### Path with "quotes" & <angle brackets>

- ID: `path-bare`
- Combined severity: `info`
- Entry: `` → Target: ``
- Findings involved: 
- Steps:

## Drift Summary

- Drifted resources: **0**
- Shadow IT (cloud-only) resources: **2**

## Compliance

- Frameworks checked: CIS-AWS

## Performance & Cost

- Duration: 0.1s
- Agent invocations: 0
- Cost: $0.0001
- Cost breakdown:
  - prove: $0.1235
  - zzz: $-0.0000
  - éphase: $10000000000000000.0000
