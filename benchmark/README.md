# CloudSecurity AF Benchmarks

This directory contains the standard benchmarks and testing strategies for CloudSecurity AF.

## 1. TerraGoat (Static IaC Benchmark)

[TerraGoat](https://github.com/bridgecrewio/terragoat) is the industry-standard "vulnerable by design" Terraform repository, maintained by Bridgecrew (Palo Alto Networks). It contains hundreds of intentional misconfigurations across AWS, GCP, and Azure.

**Why we use it:**
- Proves CloudSecurity AF can handle massive, complex enterprise repositories.
- Demonstrates the **Resource Graph** building capabilities at scale.
- Shows how our **Chain** agent connects disparate vulnerabilities into multi-hop attack paths, reducing the noise that legacy tools (like Checkov) generate.

### Running the TerraGoat Benchmark

To run CloudSecurity AF against the AWS portion of TerraGoat in Tier 1 (Static) mode:

```bash
# From the cloudsecurity-af root directory
source .venv/bin/activate
python -m cloudsecurity_af.app --repo benchmark/terragoat/terraform/aws --depth standard --format report
```

## 2. LocalStack (Live Proving Benchmark)

To demonstrate the **Tier 2 (Live Proving)** capabilities without needing a real AWS production account, we use [LocalStack](https://localstack.cloud/). LocalStack provides a fully functional local AWS cloud stack.

**Why we use it:**
- Demonstrates the `live_prover` agent's unique ability to write and execute `boto3` scripts to verify vulnerabilities.
- Proves that CloudSecurity AF can detect "Drift" (differences between the Terraform code and the live environment).
- Shows the full power of the multi-agent DAG (Recon -> Hunt -> Chain -> Prove -> Remediate) in a safe, zero-cost environment.

### Running the LocalStack Benchmark (Planned)

1. Start LocalStack:
    ```bash
    docker run --rm -it -p 4566:4566 -p 4510-4559:4510-4559 localstack/localstack
    ```
2. Deploy the vulnerable infrastructure to LocalStack using `tflocal` (a wrapper for Terraform that targets LocalStack).
3. Run CloudSecurity AF with mock AWS credentials pointing to LocalStack:
    ```bash
    export AWS_ACCESS_KEY_ID="test"
    export AWS_SECRET_ACCESS_KEY="test"
    export AWS_DEFAULT_REGION="us-east-1"
    export AWS_ENDPOINT_URL="http://localhost:4566"
    
    python -m cloudsecurity_af.app --repo benchmark/terragoat/terraform/aws --depth standard --format report
    ```
