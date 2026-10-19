import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
from app.security import AccessMiddleware,validate_configuration


def client():
    app=FastAPI()
    app.add_middleware(AccessMiddleware)
    @app.get('/scans')
    def scans():return {'ok':True}
    @app.get('/health')
    def health():return {'ok':True}
    return TestClient(app)


def test_configured_key_protects_read_and_docs(monkeypatch):
    monkeypatch.setenv('GUARDIAN_API_KEY','k'*32)
    api=client()
    for path in ['/scans','/docs','/openapi.json']:
        assert api.get(path).status_code==401
    assert api.get('/scans',headers={'Authorization':'Bearer '+'k'*32}).status_code==200
    assert api.get('/scans',headers={'Authorization':'Bearer wrong'}).status_code==401
    assert api.get('/health').status_code==200


def test_production_configuration(monkeypatch):
    monkeypatch.setenv('GUARDIAN_ENV','production')
    monkeypatch.delenv('GUARDIAN_API_KEY',raising=False)
    with pytest.raises(RuntimeError):validate_configuration()
    monkeypatch.setenv('GUARDIAN_API_KEY','k'*32)
    monkeypatch.setenv('CALLBACK_TOKEN','c'*32)
    validate_configuration()


@pytest.mark.asyncio
async def test_remote_peer_denied_without_key(monkeypatch):
    import httpx
    monkeypatch.delenv('GUARDIAN_API_KEY',raising=False)
    app=FastAPI();app.add_middleware(AccessMiddleware)
    @app.get('/scans')
    def scans():return {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('203.0.113.8',4444)),base_url='http://localhost') as api:
        assert (await api.get('/scans')).status_code==401


def test_production_callback_credentials_are_strong_and_separate(monkeypatch):
    monkeypatch.setenv('GUARDIAN_ENV','production')
    monkeypatch.setenv('GUARDIAN_API_KEY','k'*32)
    monkeypatch.setenv('CALLBACK_TOKEN','short')
    with pytest.raises(RuntimeError):validate_configuration()
    monkeypatch.setenv('CALLBACK_TOKEN','k'*32)
    with pytest.raises(RuntimeError):validate_configuration()


@pytest.mark.parametrize('headers', [
    {'Host': 'rebind.attacker.example'},
    {'Origin': 'https://attacker.example'},
    {'Origin': 'null'},
    {'Sec-Fetch-Site': 'cross-site'},
    {'Host': 'localhost:invalid'},
])
def test_keyless_local_rejects_foreign_browser_requests(monkeypatch, headers):
    monkeypatch.delenv('GUARDIAN_API_KEY', raising=False)
    monkeypatch.delenv('GUARDIAN_TENANT_KEYS', raising=False)
    monkeypatch.setenv('GUARDIAN_ENV', 'local')
    assert client().get('/scans', headers=headers).status_code == 403


def test_keyless_local_allows_local_frontend_origin(monkeypatch):
    monkeypatch.delenv('GUARDIAN_API_KEY', raising=False)
    monkeypatch.delenv('GUARDIAN_TENANT_KEYS', raising=False)
    monkeypatch.setenv('GUARDIAN_ENV', 'local')
    assert client().get('/scans', headers={'Host': '127.0.0.1:18108', 'Origin': 'http://127.0.0.1:3000'}).status_code == 200
