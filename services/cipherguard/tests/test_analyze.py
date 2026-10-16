"""
Tests for the CipherGuard /analyze endpoint contract.

These are offline tests (no registry calls). The live end-to-end scan is
exercised by the Phase A audit and the benchmark harness.
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app

AGENT_NAME = "cipherguard"

# Top-level keys trust_engine's AgentResult declares. Anything else is
# silently dropped by Pydantic before the Trust Engine ever sees it.
TRUST_ENGINE_TOP_LEVEL = {"contract_version", "agent_name", "status", "coverage", "unresolved", "decision_floor", "findings", "evidence", "callback_id"}


async def _post(payload):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/analyze", json=payload)


@pytest.mark.asyncio
async def test_health_endpoint():
    from app import readiness
    readiness._last = (__import__('time').monotonic(), {'rules_loaded':True,'pypi':True,'npm':True,'docker_hub':True})
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_unreadable_artifact_fails_closed():
    """No 'content' == the scanner could not read its input. That must never
    be reported as a clean 'pass'."""
    response = await _post({"type": "dependency", "name": "requests"})
    assert response.status_code == 200
    body = response.json()
    assert body["agent_name"] == AGENT_NAME
    assert body["status"] != "pass"
    assert body["status"] == "error"
    assert body["findings"] == []


@pytest.mark.asyncio
async def test_filename_is_never_read_from_disk():
    """Endpoint must not open() a caller-supplied path when content is absent."""
    response = await _post({"filename": "/etc/passwd"})
    body = response.json()
    assert body["status"] == "error"
    assert body["findings"] == []


@pytest.mark.asyncio
async def test_empty_manifest_is_a_valid_clean_scan():
    """An empty (but present) manifest has nothing to flag -> pass."""
    response = await _post({"filename": "requirements.txt", "content": ""})
    body = response.json()
    assert body["status"] == "pass"
    assert body["findings"] == []


@pytest.mark.asyncio
async def test_response_only_uses_fields_trust_engine_declares():
    for payload in ({"filename": "requirements.txt", "content": ""}, {"name": "x"}):
        body = (await _post(payload)).json()
        assert set(body) <= TRUST_ENGINE_TOP_LEVEL
        assert {"severity", "confidence", "total_findings", "execution_time_ms"} <= set(body["evidence"])
