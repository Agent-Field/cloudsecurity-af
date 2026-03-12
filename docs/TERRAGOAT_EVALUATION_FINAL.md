# TerraGoat Benchmark Evaluation (Final)

Date: 2026-03-12

## Benchmark Objective

Evaluate CloudSecurity as a **pre-deployment risk-prioritization system** on TerraGoat AWS Terraform.

This benchmark is used to answer:

1. Does CloudSecurity surface material infrastructure risk before deploy?
2. Does it produce decision-quality outputs that help teams fix the right issues first?
3. Where should CloudSecurity be positioned in a real security stack?

## Final Baseline Run (Product Snapshot)

- Execution: `exec_20260312_041237_fbjd66qy`
- Dataset: TerraGoat AWS Terraform (`benchmark/terragoat/terraform/aws`)
- Profile: `quick` (severity threshold `low`)
- Total resources scanned: 68
- Raw findings: 45
- Confirmed findings: 20
- Attack paths: 3
- Runtime: 2649.2s (~44.2 min)
- Mapped benchmark coverage: **33/49 = 67.3%**

## Benchmark Verdict

CloudSecurity passes the benchmark as a **high-signal prioritization layer**.

- It identifies meaningful, exploitable infrastructure risk early.
- It performs strongly on cross-resource chain logic and fix-first triage.
- It is not optimized for exhaustive long-tail control parity.

## Where Performance Is Strong

- **Risk chain visibility:** turns isolated findings into coherent risk stories.
- **Fix-first usefulness:** confirmed issues are practical to prioritize in engineering workflows.
- **Pre-deploy value:** surfaces high-impact problems before infrastructure is live.
- **High-value domains:** secrets exposure, external ingress risk, core data-path misconfigurations.

## Where Performance Is Weaker

- **Checklist completeness:** misses parts of long-tail absent-control checks.
- **Service-depth edge cases:** some nuanced service-specific controls remain uncovered.
- **Compliance-style breadth:** deterministic rule suites remain stronger for exhaustive coverage counts.

## Practical Positioning from Benchmark Results

CloudSecurity should be positioned as:

**"The shift-left decision layer for infrastructure risk."**

Not a replacement for every scanner, but the layer that answers:

"What should we fix first, and why does it matter?"

Recommended stack placement:

- Rule scanners for broad control linting.
- CloudSecurity for pre-deploy risk prioritization and attack-path context.
- Runtime CNAPP for deployed-cloud monitoring and drift.

## Final Reportable Snapshot

- **TerraGoat mapped coverage:** 33/49 (67.3%)
- **Confirmed findings:** 20
- **Attack paths:** 3
- **Best-fit claim:** pre-deployment, fix-first infrastructure risk prioritization.
