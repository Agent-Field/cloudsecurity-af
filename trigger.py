import asyncio
import argparse
import json
import sys
import httpx
from pathlib import Path


async def main():
    parser = argparse.ArgumentParser(description="CloudSecurity AF Trigger")
    parser.add_argument("--repo", required=True, help="Path to the repository to scan")
    parser.add_argument("--depth", default="standard", choices=["quick", "standard", "deep"], help="Scan depth")
    args = parser.parse_args()

    repo_path = args.repo

    payload = {"input": {"repo_url": str(repo_path), "depth": args.depth, "output_format": "json"}}

    print(f"Triggering scan on {repo_path}...")

    async with httpx.AsyncClient(timeout=600.0) as client:
        try:
            response = await client.post("http://localhost:8081/api/v1/execute/async/cloudsecurity.scan", json=payload)
            response.raise_for_status()
            print("Scan triggered successfully. Response:")
            print(json.dumps(response.json(), indent=2))
        except Exception as e:
            print(f"Failed to trigger scan: {e}")
            if hasattr(e, "response") and e.response:
                print(e.response.text)


if __name__ == "__main__":
    asyncio.run(main())
