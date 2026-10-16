"""
Live demo / verification script for the Workflow-CICD agent.

Run this with the service up (docker compose up -d workflow_cicd) to show
a clear, narratable pass/fail report for a handful of realistic GitHub
Actions workflows -- including one modeled on the real 2025 tj-actions
supply-chain compromise cited in the project doc.

Usage:
    python demo_check.py

Requires the service reachable at SERVICE_URL below. If workflow_cicd has
no published port in docker-compose.yml, add one temporarily, e.g.:
    workflow_cicd:
      ports:
        - "8001:8000"
"""

import json
import sys
import urllib.request
import urllib.error

SERVICE_URL = "http://localhost:8003/analyze"

SAMPLES = [
    {
        "label": "BAD workflow -- unpinned action + broad perms + curl|bash",
        "filename": "deploy.yml",
        "content": """
name: Deploy
on:
  pull_request_target:
    branches: [main]

permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/cool-action@main
      - name: Install deps
        run: curl -sSL https://get-tool.sh | bash
      - name: Deploy
        env:
          API_KEY: ${{ secrets.PROD_API_KEY }}
        run: ./deploy.sh
""",
    },
    {
        "label": "tj-actions style -- real 2025 supply-chain incident pattern",
        "filename": "ci.yml",
        "content": """
name: CI
on: [push]
permissions:
  contents: read
jobs:
  changed-files:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tj-actions/changed-files@v45
""",
    },
    {
        "label": "CLEAN workflow -- SHA-pinned, least-privilege",
        "filename": "ci.yml",
        "content": """
name: CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - name: Run tests
        run: pytest tests/
""",
    },
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def call_service(filename: str, content: str) -> dict:
    payload = json.dumps({"filename": filename, "content": content}).encode("utf-8")
    req = urllib.request.Request(
        SERVICE_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def print_report(label: str, result: dict) -> None:
    print("=" * 70)
    print(f"SAMPLE: {label}")
    print("-" * 70)
    print(f"  agent_name : {result.get('agent_name')}")
    print(f"  status     : {result.get('status').upper()}")
    evidence = result.get("evidence") or {}
    if "workflow_risk_score" in evidence:
        print(f"  risk score : {evidence['workflow_risk_score']}/100")

    findings = result.get("findings", [])
    if not findings:
        print("  findings   : none -- workflow is clean")
    else:
        findings_sorted = sorted(
            findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9)
        )
        print(f"  findings   : {len(findings)}")
        for f in findings_sorted:
            print(f"\n    [{f['severity'].upper()}] {f['category']}")
            print(f"      location : {f.get('location')}")
            details = f.get("details") or {}
            if details.get("message"):
                print(f"      issue    : {details['message']}")
            if details.get("remediation"):
                print(f"      fix      : {details['remediation']}")
    print()


def main() -> None:
    print("\nWORKFLOW / CI-CD AGENT -- LIVE DEMO CHECK\n")
    for sample in SAMPLES:
        try:
            result = call_service(sample["filename"], sample["content"])
        except urllib.error.URLError as exc:
            print(f"ERROR calling service for '{sample['label']}': {exc}")
            print(f"Is the service running and reachable at {SERVICE_URL}?")
            sys.exit(1)
        print_report(sample["label"], result)

    print("=" * 70)
    print("Demo complete -- 3/3 samples analyzed successfully.")


if __name__ == "__main__":
    main()