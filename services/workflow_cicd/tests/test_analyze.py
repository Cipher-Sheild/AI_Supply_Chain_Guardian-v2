"""
Standalone tests — hit this service's own /analyze directly, no trust_engine
or Docker Compose required. Run with: pytest tests/ -v
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


BAD_WORKFLOW = """
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
"""

# Mirrors the real-world basis named in the project doc (§8.2): a popular
# third-party action pinned to a mutable ref, as in the 2025 tj-actions
# supply-chain compromise.
TJ_ACTIONS_STYLE_WORKFLOW = """
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
"""

CLEAN_WORKFLOW = """
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
"""

UNPARSABLE_WORKFLOW = "this: is: not: valid: yaml: [["


def analyze(content, filename="ci.yml"):
    resp = client.post("/analyze", json={"filename": filename, "content": content})
    assert resp.status_code == 200
    return resp.json()


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["agent_name"] == "workflow_cicd"


def test_bad_workflow_flags_all_three_categories():
    body = analyze(BAD_WORKFLOW, "deploy.yml")

    assert body["agent_name"] == "workflow_cicd"
    assert body["status"] == "fail"

    categories = {f["category"] for f in body["findings"]}
    assert "unpinned-action" in categories
    assert "broad-permissions-plus-pull-request-target" in categories
    assert "curl-pipe-bash" in categories

    unpinned = [f for f in body["findings"] if f["category"] == "unpinned-action"]
    assert len(unpinned) == 2
    severities = {f["severity"] for f in unpinned}
    assert "high" in severities   # @main
    assert "medium" in severities  # @v4

    assert all("confidence" in f and f["confidence"] is not None for f in body["findings"])

    # The permissions finding must point at the permissions line (7), not the
    # pull_request_target trigger line.
    perms = [f for f in body["findings"]
             if f["category"] == "broad-permissions-plus-pull-request-target"][0]
    assert perms["location"] == "deploy.yml:7"
    assert perms["details"]["trigger_location"] == "line 4"


def test_broad_permissions_check_requires_dangerous_trigger():
    workflow = """
name: Release
on: [push]
permissions: write-all
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
"""
    body = analyze(workflow, "release.yml")
    categories = {f["category"] for f in body["findings"]}
    assert "broad-permissions-plus-pull-request-target" not in categories


def test_tj_actions_style_unpinned_tag_is_flagged():
    body = analyze(TJ_ACTIONS_STYLE_WORKFLOW)
    unpinned = [f for f in body["findings"] if f["category"] == "unpinned-action"]
    assert len(unpinned) == 2  # checkout@v4 and changed-files@v45
    assert body["status"] == "warn"  # both are tags -> medium -> warn, not fail


def test_clean_workflow_passes():
    body = analyze(CLEAN_WORKFLOW)
    assert body["status"] == "pass"
    assert body["findings"] == []


# --- regression tests for the six scanner bugs ---------------------------


def test_arbitrary_branch_ref_is_high_not_medium():
    workflow = """
on: [push]
jobs:
  a:
    steps:
      - uses: evil-org/action@develop
"""
    body = analyze(workflow)
    f = body["findings"][0]
    assert f["severity"] == "high"
    assert f["details"]["ref_type"] == "branch"
    assert body["status"] == "fail"


def test_job_level_reusable_workflow_is_checked():
    workflow = """
on: [push]
jobs:
  call:
    uses: org/repo/.github/workflows/deploy.yml@main
    secrets: inherit
"""
    body = analyze(workflow)
    assert [f["category"] for f in body["findings"]] == ["unpinned-action"]
    assert body["findings"][0]["severity"] == "high"


def test_job_level_permissions_are_checked():
    workflow = """
on:
  pull_request_target:
jobs:
  a:
    permissions: write-all
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
"""
    body = analyze(workflow)
    f = [x for x in body["findings"]
         if x["category"] == "broad-permissions-plus-pull-request-target"][0]
    assert f["severity"] == "critical"
    assert f["details"]["scope"] == "job 'a'"


def test_repeated_action_reports_distinct_lines():
    workflow = """on: [push]
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
  b:
    steps:
      - uses: actions/checkout@v4
"""
    body = analyze(workflow)
    locations = [f["location"] for f in body["findings"]]
    assert len(set(locations)) == 2


def test_curl_pipe_variants_are_caught():
    for cmd in [
        "curl -sSL https://x.sh | sudo -E bash",
        "curl -sSL https://x.sh | tee /tmp/x | bash",
        "wget -qO- https://x.sh | sh",
        "curl https://x.py | python3",
        "iwr https://x.ps1 | iex",
    ]:
        workflow = f"""
on: [push]
jobs:
  a:
    steps:
      - run: {cmd}
"""
        body = analyze(workflow)
        cats = [f["category"] for f in body["findings"]]
        assert "curl-pipe-bash" in cats, cmd


def test_checksum_verified_download_is_not_flagged():
    workflow = """
on: [push]
jobs:
  a:
    steps:
      - run: |
          curl -o tool.sh https://x.sh
          sha256sum -c sums.txt
          bash tool.sh
"""
    body = analyze(workflow)
    assert body["status"] == "pass"


# --- artifact-type gating -------------------------------------------------


def test_non_workflow_artifact_returns_stub_not_fail():
    """orchestration.py sends every artifact to all 7 detectors. A Python
    file is not a workflow-security verdict — it must not report fail."""
    body = analyze("import os\nprint('hello')\n", "app.py")
    assert body["status"] == "stub"
    assert body["findings"] == []
    assert body["evidence"]["reason"]


def test_dockerfile_returns_stub():
    body = analyze("FROM python:3.11-slim\nWORKDIR /app\n", "Dockerfile")
    assert body["status"] == "stub"


def test_yaml_that_is_not_a_workflow_returns_stub():
    body = analyze("name: something\ndescription: not a workflow\n", "config.yml")
    assert body["status"] == "stub"


def test_unparsable_yaml_named_as_workflow_returns_error():
    body = analyze(UNPARSABLE_WORKFLOW, "broken.yml")
    assert body["status"] == "error"
    assert body["evidence"] is not None


def test_missing_filename_still_works():
    """filename is optional — a required field absent from trust_engine's
    shared artifact payload would 422 and get our result discarded."""
    resp = client.post("/analyze", json={"content": BAD_WORKFLOW})
    assert resp.status_code == 200
    assert resp.json()["status"] == "fail"


def test_undeclared_request_fields_are_rejected():
    resp = client.post(
        "/analyze",
        json={"content": CLEAN_WORKFLOW, "filename": "ci.yml",
              "artifact_type": "workflow", "scan_id": "abc-123", "ai_tool_source": "cursor"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"][0]["type"] == "extra_forbidden"


def test_response_uses_version_one_contract():
    body = analyze(CLEAN_WORKFLOW)
    assert set(body) == {"contract_version", "agent_name", "status", "coverage", "unresolved", "decision_floor", "findings", "evidence", "callback_id"}
    for f in analyze(BAD_WORKFLOW, "deploy.yml")["findings"]:
        assert set(f) == {"category", "severity", "confidence", "location", "details", "reason", "remediation", "hard_block", "score"}

def test_risk_score_reflects_severity():
    """Project doc 7.5: the agent outputs a workflow risk score alongside
    line-level flags."""
    clean = analyze(CLEAN_WORKFLOW)
    bad = analyze(BAD_WORKFLOW, "deploy.yml")

    assert clean["evidence"]["workflow_risk_score"] == 100
    # 1 critical (40) + 2 high (20+20) + 1 medium (8) -> 100 - 88
    assert bad["evidence"]["workflow_risk_score"] == 12
    assert clean["evidence"]["workflow_risk_score"] > bad["evidence"]["workflow_risk_score"]


def test_non_workflow_has_no_risk_score():
    body = analyze("import os\n", "app.py")
    assert "workflow_risk_score" not in body["evidence"]