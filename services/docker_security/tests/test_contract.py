"""
Contract tests -- pin the Phase A audit finding that six agent-specific fields
(risk_score, hardened_artifact, ...) were being emitted at the top level, where
trust_engine's AgentResult silently drops them. They must live in `evidence`.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

TRUST_ENGINE_TOP_LEVEL = {"contract_version", "agent_name", "status", "coverage", "unresolved", "decision_floor", "findings", "evidence", "callback_id"}
EVIDENCE_FIELDS = {"risk_score", "severity", "total_findings",
                   "execution_time_ms", "hardened_artifact"}

DOCKERFILE = "FROM ubuntu:latest\nUSER root\nEXPOSE 22\nRUN apt-get update\n"


def test_no_top_level_fields_are_silently_dropped():
    body = client.post("/analyze", json={"type": "dockerfile", "filename": "Dockerfile",
                                         "content": DOCKERFILE}).json()
    assert set(body) <= TRUST_ENGINE_TOP_LEVEL


def test_agent_specific_output_survives_in_evidence():
    body = client.post("/analyze", json={"type": "dockerfile", "filename": "Dockerfile",
                                         "content": DOCKERFILE}).json()
    ev = body["evidence"]
    assert EVIDENCE_FIELDS <= set(ev)
    assert ev["risk_score"] > 0
    assert ev["hardened_artifact"] is not None      # the hardened Dockerfile reaches the Trust Engine
    assert ev["total_findings"] == len(body["findings"])


def test_empty_input_response_keeps_the_same_shape():
    body = client.post("/analyze", json={"content": ""}).json()
    assert set(body) <= TRUST_ENGINE_TOP_LEVEL
    assert body["status"] == "error"
    assert body["coverage"] == "none"
