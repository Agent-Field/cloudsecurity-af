import asyncio
import argparse
import json
import sys
from pathlib import Path

from cloudsecurity_af.schemas.input import CloudSecurityInput, CloudConfig
from cloudsecurity_af.orchestrator import ScanOrchestrator
from cloudsecurity_af.app import app


async def main():
    parser = argparse.ArgumentParser(description="CloudSecurity AF CLI")
    parser.add_argument("--repo", required=True, help="Path to the repository to scan")
    parser.add_argument("--depth", default="standard", choices=["quick", "standard", "deep"], help="Scan depth")
    parser.add_argument("--format", default="json", choices=["json", "sarif", "report"], help="Output format")
    args = parser.parse_args()

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"Error: Repository path {repo_path} does not exist.")
        sys.exit(1)

    input_data = CloudSecurityInput(
        repo_url=str(repo_path),
        depth=args.depth,
        cloud_config=None,  # Tier 1 (Static)
        output_format=args.format,
    )

    print(f"Starting CloudSecurity AF scan on {repo_path} (Depth: {args.depth})")
    orchestrator = ScanOrchestrator(app, input_data)

    try:
        result = await orchestrator.run()

        if args.format == "json":
            print(result.model_dump_json(indent=2))
        elif args.format == "sarif":
            print(result.sarif_output)
        elif args.format == "report":
            print(result.markdown_report)

    except Exception as e:
        print(f"Scan failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
