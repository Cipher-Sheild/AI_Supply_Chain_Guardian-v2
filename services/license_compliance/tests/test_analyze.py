"""
Tests for the License Compliance microservice.

Network calls (PyPI/npm registry) and Redis are mocked/stubbed so this
suite runs deterministically and fast, without needing real network
access or a running Redis instance -- app.cache.LicenseCache already
fails open when Redis is unreachable, so tests exercise that same path
by simply never connecting it (self._client stays None).

ScanCode itself is NOT exercised end-to-end here (it's a heavy optional
dependency -- see app/license_lookup.py's defensive import); instead,
`_run_scancode_fallback` is monkeypatched directly for the one test
that needs the fallback path, so the *pipeline's* handling of a
fallback result is verified without requiring scancode-toolkit to be
installed in the test environment.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

import app.main as main_module
from app.cache import LicenseCache
from app.main import app

AGENT_NAME = "license_compliance"


class _FakeCache(LicenseCache):
    """In-memory stand-in for Redis so tests don't need a real server."""

    def __init__(self):
        super().__init__(redis_url="redis://unused", ttl_seconds=999)
        self._store: dict[str, dict] = {}

    async def connect(self) -> None:  # never touches real Redis
        return None

    async def close(self) -> None:
        return None

    async def get(self, key: str):
        return self._store.get(key)

    async def set(self, key: str, value: dict, ttl_seconds=None) -> None:
        self._store[key] = value


@pytest.fixture(autouse=True)
async def _wire_fake_infra(monkeypatch):
    """Give every test a fresh fake cache and a real (but request-mocked) http client."""
    fake_cache = _FakeCache()
    monkeypatch.setattr(main_module, "_cache", fake_cache)

    async with AsyncClient() as client:
        monkeypatch.setattr(main_module, "_http_client", client)
        yield fake_cache


def _mock_pypi_response(monkeypatch, payload: dict):
    async def _fake_get(self, url, timeout=8.0):
        class _Resp:
            status_code = 200

            def json(self_inner):
                return payload

        return _Resp()

    monkeypatch.setattr("httpx.AsyncClient.get", _fake_get)


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
async def test_analyze_empty_manifest_passes():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/analyze", json={"type": "dependency", "content": "", "filename": "requirements.txt"})
    assert response.status_code == 200
    body = response.json()
    assert body["agent_name"] == AGENT_NAME
    assert body["status"] == "pass"
    assert body["findings"] == []


@pytest.mark.asyncio
async def test_clean_mit_dependency_is_compliant(monkeypatch):
    _mock_pypi_response(
        monkeypatch,
        {
            "info": {
                "classifiers": ["License :: OSI Approved :: MIT License"],
                "license": "MIT",
                "requires_dist": [],
            }
        },
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/analyze",
            json={"type": "dependency", "content": "requests==2.31.0", "filename": "requirements.txt"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "pass"
    assert body["findings"] == []
    assert body["evidence"]["compliant_count"] == 1


@pytest.mark.asyncio
async def test_gpl_dependency_is_a_conflict(monkeypatch):
    _mock_pypi_response(
        monkeypatch,
        {
            "info": {
                "classifiers": ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"],
                "license": "GPL-3.0",
                "requires_dist": [],
            }
        },
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/analyze",
            json={"type": "dependency", "content": "copyleft-pkg==1.0.0", "filename": "requirements.txt"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "fail"
    assert "severity" not in body  # real AgentResult has no top-level severity
    assert len(body["findings"]) == 1
    finding = body["findings"][0]
    assert finding["category"] == "license_conflict"
    assert finding["severity"] in ("high", "critical")
    assert "package" not in finding and "verdict" not in finding  # old flat shape must be gone
    details = finding["details"]
    assert details["verdict"] == "conflict"
    assert "denied" in details["reason"].lower() or "copyleft" in details["reason"].lower()
    assert "GPL" in details["license"]


@pytest.mark.asyncio
async def test_missing_license_needs_review(monkeypatch):
    _mock_pypi_response(monkeypatch, {"info": {"classifiers": [], "license": "", "requires_dist": []}})
    # Force the scancode fallback branch to report "found nothing", as
    # if scancode-toolkit isn't installed / found no confident match --
    # exercises the pipeline's handling without requiring the real
    # (heavy) scancode-toolkit package in the test environment.
    monkeypatch.setattr(
        "app.license_lookup._run_scancode_fallback",
        lambda text: ([], None, 0.0, ["ScanCode unavailable in test environment."]),
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/analyze",
            json={"type": "dependency", "content": "mystery-pkg==0.1.0", "filename": "requirements.txt"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "warn"
    assert "severity" not in body
    finding = body["findings"][0]
    assert finding["category"] == "license_review"
    assert finding["severity"] == "medium"
    assert finding["details"]["verdict"] == "needs_review"


@pytest.mark.asyncio
async def test_cache_hit_skips_registry_call(monkeypatch, _wire_fake_infra):
    fake_cache = _wire_fake_infra
    call_count = {"n": 0}

    async def _counting_get(self, url, timeout=8.0):
        call_count["n"] += 1

        class _Resp:
            status_code = 200

            def json(self_inner):
                return {"info": {"classifiers": ["License :: OSI Approved :: MIT License"], "license": "MIT", "requires_dist": []}}

        return _Resp()

    monkeypatch.setattr("httpx.AsyncClient.get", _counting_get)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post(
            "/analyze", json={"type": "dependency", "content": "requests==2.31.0", "filename": "requirements.txt"}
        )
        assert first.status_code == 200
        assert call_count["n"] == 1

        second = await client.post(
            "/analyze", json={"type": "dependency", "content": "requests==2.31.0", "filename": "requirements.txt"}
        )
        assert second.status_code == 200
        # Second scan of the identical pinned dependency should hit the
        # cache, not the registry again.
        assert call_count["n"] == 1
        assert second.json()["status"] == "pass"


@pytest.mark.asyncio
async def test_dual_licensed_mit_or_gpl_is_compliant_via_mit_branch(monkeypatch):
    _mock_pypi_response(
        monkeypatch,
        {
            "info": {
                "classifiers": [
                    "License :: OSI Approved :: MIT License",
                    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
                ],
                "license": "",
                "requires_dist": [],
            }
        },
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/analyze",
            json={"type": "dependency", "content": "dual-licensed-pkg==1.0.0", "filename": "requirements.txt"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "pass"


@pytest.mark.asyncio
async def test_skipped_entries_are_reported_not_silently_dropped(monkeypatch):
    """
    A `-r` include, a git-protocol npm dependency, etc. must show up in
    evidence.skipped with a reason -- not silently vanish with no trace.
    """
    _mock_pypi_response(
        monkeypatch,
        {"info": {"classifiers": ["License :: OSI Approved :: MIT License"], "license": "MIT", "requires_dist": []}},
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/analyze",
            json={
                "type": "dependency",
                "filename": "requirements.txt",
                "content": "requests==2.31.0\n-r other-requirements.txt\n-e git+https://example.com/foo.git#egg=foo\n",
            },
        )
    assert response.status_code == 200
    body = response.json()
    skipped = body["evidence"]["skipped"]
    assert len(skipped) == 2
    reasons = {s["raw"]: s["reason"] for s in skipped}
    assert "include" in reasons["-r other-requirements.txt"].lower()
    assert "editable" in reasons["-e git+https://example.com/foo.git#egg=foo"].lower()


@pytest.mark.asyncio
async def test_npm_package_json_gpl_conflict(monkeypatch):
    async def _fake_get(self, url, timeout=8.0):
        class _Resp:
            status_code = 200

            def json(self_inner):
                return {"license": "GPL-3.0-only", "dependencies": {}}

        return _Resp()

    monkeypatch.setattr("httpx.AsyncClient.get", _fake_get)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/analyze",
            json={
                "type": "dependency",
                "filename": "package.json",
                "content": '{"dependencies": {"copyleft-lib": "1.0.0"}}',
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "fail"
    assert body["findings"][0]["details"]["ecosystem"] == "node"


@pytest.mark.asyncio
async def test_non_dependency_artifact_short_circuits_to_stub():
    """
    Regression test for the Phase A audit fix: a plain code file must
    never reach extract_dependencies -- without the type/filename guard,
    its `import`/`def`/`os.system` tokens get matched by the
    requirements.txt-style content heuristic and misparsed as package
    names (the real bug Ahmed's audit found).
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/analyze",
            json={
                "type": "code",
                "filename": "utils.py",
                "content": "import os\n\ndef helper():\n    os.system('echo hi')\n    return 42\n",
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "stub"
    assert body["findings"] == []
    assert body["evidence"] is None


@pytest.mark.asyncio
async def test_unrecognized_filename_without_type_short_circuits_to_stub():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/analyze",
            json={"filename": "notes.txt", "content": "requests\nparamiko\n"},
        )
    assert response.status_code == 200
    assert response.json()["status"] == "stub"
@pytest.mark.asyncio
async def test_license_file_routes_to_native_text_policy():
    from app.native_license import ROOT
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
        response=await client.post('/analyze',json={'filename':'LICENSE','type':'license','content':(ROOT/'MIT.txt').read_text()})
        assert response.status_code==200
        result=response.json()
        assert result['status']=='pass' and result['coverage']=='full'
        assert result['evidence']['all_dependencies'][0]['license']=='MIT'
        response=await client.post('/analyze',json={'filename':'COPYING','type':'license','content':'All rights reserved; commercial use prohibited.'})
        result=response.json()
        assert result['unresolved'] and result['decision_floor']=='review'
        assert result['findings'][0]['category']=='license_review'

@pytest.mark.asyncio
async def test_identified_restrictive_license_does_not_default_to_permissive():
    from app.native_license import ROOT
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
        response=await client.post('/analyze',json={'filename':'LICENSE','type':'license','content':(ROOT/'CC-BY-NC-4.0.txt').read_text()})
        result=response.json()
        assert result['status']=='warn'
        assert result['evidence']['all_dependencies'][0]['verdict']=='needs_review'
