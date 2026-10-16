"""
Contract tests for /analyze -- pin the two defects the Phase A audit found:
  1. the service must read the orchestrator's {content, filename} shape;
  2. an unreadable artifact must never be reported as a clean 'pass'.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

# Top-level keys trust_engine's AgentResult declares; the rest are dropped silently.
TRUST_ENGINE_TOP_LEVEL = {"contract_version", "agent_name", "status", "coverage", "unresolved", "decision_floor", "findings", "evidence", "callback_id"}

AWS_CONTENT = (
    'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
    'AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
)


def test_orchestrator_shape_content_filename_is_scanned():
    body = client.post("/analyze", json={"type": "code", "filename": "config.py",
                                         "content": AWS_CONTENT}).json()
    assert body["status"] == "fail"
    assert len(body["findings"]) >= 1
    assert body["findings"][0]["category"] == "aws_access_key"


def test_legacy_files_shape_still_supported():
    body = client.post("/analyze", json={"files": [{"path": "config.py",
                                                    "content": AWS_CONTENT}]}).json()
    assert body["status"] == "fail"


def test_unreadable_artifact_is_not_a_clean_pass():
    body = client.post("/analyze", json={"type": "code"}).json()
    assert body["status"] != "pass"
    assert body["status"] == "error"
    assert body["findings"] == []


def test_response_only_uses_fields_trust_engine_declares():
    for payload in ({"filename": "a.py", "content": AWS_CONTENT}, {"type": "code"}):
        body = client.post("/analyze", json=payload).json()
        assert set(body) <= TRUST_ENGINE_TOP_LEVEL
        assert {"severity", "confidence", "total_findings", "execution_time_ms"} <= set(body["evidence"])
