import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

AGENT_NAME = "docker_security"

@pytest.mark.asyncio
async def test_health_endpoint(monkeypatch,tmp_path):
    from app import readiness
    readiness._last = (__import__('time').monotonic(), {'rules_loaded':True,'pypi':True,'npm':True,'docker_hub':True})
    monkeypatch.setattr("app.main.shutil.which", lambda tool: "/bin/"+tool)
    from app import image_jobs
    monkeypatch.setenv("DOCKER_CALLBACK_OUTBOX_PATH",str(tmp_path/"jobs.sqlite3"))
    await image_jobs.start()
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
    finally:await image_jobs.stop()
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == AGENT_NAME

@pytest.mark.asyncio
async def test_analyze_dockerfile():
    df_content = """
    FROM ubuntu:latest
    USER root
    RUN apt-get update && apt-get install -y curl
    EXPOSE 8000
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/analyze", json={
            "artifact_type": "dockerfile",
            "content": df_content,
            "options": {"enable_cve_scan": False}
        })
    assert response.status_code == 200
    res = response.json()
    assert res["agent_name"] == AGENT_NAME
    assert res["status"] in ["warn", "fail", "error"]
    assert res["evidence"]["total_findings"] > 0
    assert res["evidence"]["risk_score"] > 0
    assert res["evidence"]["hardened_artifact"] is not None

@pytest.mark.asyncio
async def test_analyze_compose():
    compose_content = """
    version: '3.8'
    services:
      web:
        image: nginx:latest
        privileged: true
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/analyze", json={
            "artifact_type": "compose",
            "content": compose_content
        })
    assert response.status_code == 200
    res = response.json()
    assert res["agent_name"] == AGENT_NAME
    assert res["status"] == "fail"
    assert res["evidence"]["risk_score"] == 100
