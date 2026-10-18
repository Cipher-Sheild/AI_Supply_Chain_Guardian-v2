"""
Sanity-check tests for the trust_engine microservice scaffold.

Since trust_engine's whole job is calling the other 7 services over
HTTP, and those aren't running in a unit-test process, `_call_detector`
is monkeypatched to return dummy AgentResults instead of making real
network calls. This still exercises the LangGraph fan-out/fan-in graph,
the fusion logic, and the /analyze endpoint end-to-end within this
service. The real inter-service HTTP wiring is meant to be verified with
`docker compose up` and a live call, per the project prompt (§10) —
not by this unit test.
"""

import os

os.environ.setdefault("CIPHERGUARD_URL", "http://cipherguard:8000/analyze")
os.environ.setdefault("CODE_SECURITY_URL", "http://code_security:8000/analyze")
os.environ.setdefault("SECRET_DETECTION_URL", "http://secret_detection:8000/analyze")
os.environ.setdefault("DOCKER_SECURITY_URL", "http://docker_security:8000/analyze")
os.environ.setdefault("WORKFLOW_CICD_URL", "http://workflow_cicd:8000/analyze")
os.environ.setdefault("LICENSE_COMPLIANCE_URL", "http://license_compliance:8000/analyze")
os.environ.setdefault("PROMPT_INJECTION_URL", "http://prompt_injection:8000/analyze")

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.schemas import AgentResult
import app.orchestration as orchestration

# Captured before the autouse fixture below monkeypatches
# orchestration._call_detector for every test in this file.
_REAL_CALL_DETECTOR = orchestration._call_detector


@pytest.fixture(autouse=True)
def called_agents(monkeypatch):
    """Patch the routed dispatch primitive and capture which agent names
    were actually invoked, in call order.

    The routed path calls `_request_detector` (which raises on failure so
    the orchestrator can record result=None + error_reason); the never-
    raising `_call_detector` wrapper is left real so
    test_transport_failure_reports_error_not_fail is unchanged.
    """
    calls: list[str] = []

    async def _fake_request_detector(client, agent_name, url, artifact):
        calls.append(agent_name)
        return AgentResult(agent_name=agent_name, status="pass")

    monkeypatch.setattr(orchestration, "_request_detector", _fake_request_detector)
    return calls


async def _post_analyze(payload: dict):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/analyze", json=payload)


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"


@pytest.mark.asyncio
async def test_code_artifact_dispatches_only_to_routed_agents(called_agents):
    """Replaces test_analyze_fans_out_to_all_seven_detectors_and_fuses_result:
    calling all 7 every time is no longer correct by design -- the router
    decides who runs."""
    response = await _post_analyze({"type": "code", "content": "print('hi')"})
    assert response.status_code == 200
    expected = {"code_security", "secret_detection", "prompt_injection"}
    assert set(called_agents) == expected
    assert len(called_agents) == 3            # each called exactly once
    body = response.json()
    assert {r["agent_name"] for r in body["detector_results"]} == expected
    assert body["trust_score"] == 100
    assert body["recommendation"] == "accept"


@pytest.mark.asyncio
async def test_dockerfile_artifact_dispatches_only_to_routed_agents(called_agents):
    response = await _post_analyze({"type": "dockerfile", "content": "FROM python:3.11-slim"})
    assert response.status_code == 200
    assert set(called_agents) == {"docker_security", "secret_detection"}
    assert len(called_agents) == 2


@pytest.mark.asyncio
async def test_unrecognised_type_dispatches_only_secret_detection_and_never_accepts(called_agents):
    response = await _post_analyze({"filename": "config.yml", "content": "key: value"})
    assert response.status_code == 200
    assert called_agents == ["secret_detection"]
    body = response.json()
    assert body["recommendation"] != "accept"
    assert "partial coverage" in body["explanation"]


@pytest.mark.asyncio
async def test_lockfile_dispatches_to_no_agents(called_agents):
    response = await _post_analyze({"filename": "composer.lock", "content": "{}"})
    assert response.status_code == 200
    assert called_agents == []
    body = response.json()
    assert body["detector_results"] == []
    assert body["recommendation"] != "accept"


@pytest.mark.asyncio
async def test_invalid_explicit_type_is_422_not_500(called_agents):
    response = await _post_analyze({"type": "banana", "content": "x"})
    assert response.status_code == 422
    assert called_agents == []


@pytest.mark.asyncio
async def test_routed_agent_transport_failure_records_error_and_floors_review(monkeypatch):
    async def _boom(client, agent_name, url, artifact):
        if agent_name == "code_security":
            raise orchestration.DetectorCallError("timeout after 10.0s")
        return AgentResult(agent_name=agent_name, status="pass")

    monkeypatch.setattr(orchestration, "_request_detector", _boom)
    final = await orchestration._compiled_graph.ainvoke({
        "files": [{"type": "code", "content": "print('hi')", "filename": "app.py"}],
        "routing": [], "results": [], "pending_callbacks": [], "routing_notes": [],
        "trust_result": {},
    })
    records = {r.agent: r for r in final["results"]}
    assert set(records) == {"code_security", "secret_detection", "prompt_injection"}
    cs = records["code_security"]
    assert (cs.agent_ran, cs.status, cs.result, cs.error_reason) == (
        True, "error", None, "timeout after 10.0s"
    )
    assert final["trust_result"]["recommendation"] == "review"
    assert final["request_id"]                       # generated by _route


@pytest.mark.asyncio
async def test_results_are_not_duplicated_by_the_reducer(called_agents):
    """`results` has an operator.add reducer; nodes must return partial
    updates or every downstream node would re-append the records."""
    final = await orchestration._compiled_graph.ainvoke({
        "files": [{"type": "code", "content": "x"}],
        "routing": [], "results": [], "pending_callbacks": [], "routing_notes": [],
        "trust_result": {},
    })
    assert len(final["results"]) == 3


@pytest.mark.asyncio
async def test_pending_result_populates_pending_callbacks(monkeypatch):
    async def _pending(client, agent_name, url, artifact):
        if agent_name == "prompt_injection":
            return AgentResult(agent_name=agent_name, status="pending", callback_id="cb-9")
        return AgentResult(agent_name=agent_name, status="pass")

    monkeypatch.setattr(orchestration, "_request_detector", _pending)
    final = await orchestration._compiled_graph.ainvoke({
        "files": [{"type": "code", "content": "x", "filename": "a.py"}],
        "routing": [], "results": [], "pending_callbacks": [], "routing_notes": [],
        "trust_result": {},
    })
    assert [(p.file, p.agent, p.callback_id) for p in final["pending_callbacks"]] == [
        ("a.py", "prompt_injection", "cb-9")
    ]
    assert final["trust_result"]["explanation"].startswith(
        "[PROVISIONAL — awaiting callback cb-9]"
    )


@pytest.mark.asyncio
async def test_transport_failure_reports_error_not_fail():
    """
    Phase A audit finding: "fail" was overloaded to mean both "the scanner
    ran and found critical issues" and "the scanner crashed/was
    unreachable," and the fusion logic could not tell them apart. This
    pins the fix: a genuine transport failure (unreachable host, timeout,
    non-2xx) must surface as "error", a status "fail" never carries.
    """
    from httpx import AsyncClient as RealAsyncClient

    async with RealAsyncClient() as client:
        result = await _REAL_CALL_DETECTOR(
            client, "cipherguard", "http://this-host-does-not-exist:9999/analyze", {}
        )
    assert result.status == "error"
    assert result.findings == []


@pytest.mark.asyncio
async def test_agent_result_accepts_error_status():
    """A detector legitimately returning status="error" (e.g. it could not
    read its input) must parse through trust_engine's own AgentResult
    rather than being rejected -- previously only pass/warn/fail/stub
    were declared, so "error" responses failed Pydantic validation here."""
    parsed = AgentResult(agent_name="cipherguard", status="error", findings=[])
    assert parsed.status == "error"


@pytest.mark.asyncio
async def test_detector_reported_error_names_its_reason_and_floors_review(monkeypatch):
    """A detector that ran but answered status="error" (e.g. prompt_injection
    whose LLM judge could not decide) floors at Review, and the explanation
    carries the detector's own evidence["error"] instead of the generic
    "agent reported error"."""
    reason = "Stage 3 LLM judge could not judge 1 escalated span(s) (a.py:1): LLM judge call failed"

    async def _fake(client, agent_name, url, artifact):
        if agent_name == "prompt_injection":
            return AgentResult(agent_name=agent_name, status="error", evidence={"error": reason})
        return AgentResult(agent_name=agent_name, status="pass")

    monkeypatch.setattr(orchestration, "_request_detector", _fake)
    final = await orchestration._compiled_graph.ainvoke({
        "files": [{"type": "code", "content": "x", "filename": "a.py"}],
        "routing": [], "results": [], "pending_callbacks": [], "routing_notes": [],
        "trust_result": {},
    })
    pi = next(r for r in final["results"] if r.agent == "prompt_injection")
    assert (pi.status, pi.error_reason) == ("error", reason)
    assert final["trust_result"]["recommendation"] == "review"
    assert reason in final["trust_result"]["explanation"]
    assert "agent reported error" not in final["trust_result"]["explanation"]


def test_container_scope_is_explicit_and_default_stays_resolved():
 from app.orchestration import canonical_request
 from app.routing import route_file
 decision=route_file('FROM scratch\n','Dockerfile')
 default=canonical_request({'content':'FROM scratch\n'},decision)
 assert default['options']['enable_cve_scan'] is True
 text=canonical_request({'content':'FROM scratch\n','options':{'scan_scope':'supplied_text','enable_cve_scan':True}},decision)
 assert text['options']['enable_cve_scan'] is False
 resolved=canonical_request({'content':'FROM scratch\n','options':{'scan_scope':'resolved_images','enable_cve_scan':False}},decision)
 assert resolved['options']['enable_cve_scan'] is True
