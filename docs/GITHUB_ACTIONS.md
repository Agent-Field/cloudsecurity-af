# GitHub Actions Integration

## Tier 1: Static Scan (no credentials needed)

```yaml
name: cloudsecurity-scan
on:
  pull_request:
    paths:
      - '**/*.tf'
      - '**/*.tfvars'
      - '**/*.yaml'
      - '**/*.yml'
      - '**/Dockerfile'

jobs:
  infrastructure-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Trigger CloudSecurity Scan
        run: |
          RESPONSE=$(curl -sS -X POST "$AGENTFIELD_SERVER/api/v1/execute/async/cloudsecurity.scan" \
            -H "Content-Type: application/json" \
            -d '{
              "input": {
                "repo_url": ".",
                "branch": "${{ github.head_ref }}",
                "commit_sha": "${{ github.event.pull_request.head.sha }}",
                "base_commit_sha": "${{ github.event.pull_request.base.sha }}",
                "is_pr": true,
                "depth": "quick",
                "output_formats": ["sarif", "json"]
              }
            }')
          echo "execution_id=$(echo "$RESPONSE" | jq -r '.execution_id')" >> "$GITHUB_ENV"
        env:
          AGENTFIELD_SERVER: ${{ secrets.AGENTFIELD_SERVER }}

      - name: Wait for results
        run: |
          for i in {1..60}; do
            RESULT=$(curl -sS "$AGENTFIELD_SERVER/api/v1/executions/$execution_id")
            STATUS=$(echo "$RESULT" | jq -r '.status')
            [ "$STATUS" = "succeeded" ] && { echo "$RESULT" | jq -r '.result.sarif' > results.sarif; exit 0; }
            [ "$STATUS" = "failed" ] && { echo "Scan failed"; exit 1; }
            sleep 5
          done
          echo "Timed out"; exit 1
        env:
          AGENTFIELD_SERVER: ${{ secrets.AGENTFIELD_SERVER }}

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Tier 2: Live Verification (with cloud credentials)

```yaml
name: cloudsecurity-prove
on:
  pull_request:
    paths:
      - '**/*.tf'
      - '**/*.tfvars'

jobs:
  infrastructure-prove:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1

      - name: Trigger CloudSecurity Prove
        run: |
          RESPONSE=$(curl -sS -X POST "$AGENTFIELD_SERVER/api/v1/execute/async/cloudsecurity.prove" \
            -H "Content-Type: application/json" \
            -d '{
              "input": {
                "repo_url": ".",
                "branch": "${{ github.head_ref }}",
                "is_pr": true,
                "depth": "standard",
                "cloud": {
                  "provider": "aws",
                  "regions": ["us-east-1", "us-west-2"],
                  "enable_drift_detection": true,
                  "enable_attack_paths": true
                },
                "output_formats": ["sarif", "json"],
                "compliance_frameworks": ["cis-aws"]
              }
            }')
          echo "execution_id=$(echo "$RESPONSE" | jq -r '.execution_id')" >> "$GITHUB_ENV"
        env:
          AGENTFIELD_SERVER: ${{ secrets.AGENTFIELD_SERVER }}

      - name: Wait for results
        run: |
          for i in {1..120}; do
            RESULT=$(curl -sS "$AGENTFIELD_SERVER/api/v1/executions/$execution_id")
            STATUS=$(echo "$RESULT" | jq -r '.status')
            [ "$STATUS" = "succeeded" ] && { echo "$RESULT" | jq -r '.result.sarif' > results.sarif; exit 0; }
            [ "$STATUS" = "failed" ] && { echo "Prove failed"; exit 1; }
            sleep 10
          done
          echo "Timed out"; exit 1
        env:
          AGENTFIELD_SERVER: ${{ secrets.AGENTFIELD_SERVER }}

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```
