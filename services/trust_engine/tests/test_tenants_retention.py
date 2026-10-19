import json
from datetime import datetime,timedelta
import pytest
import httpx
from sqlalchemy import select,update,func
from app.main import app
from app.pending_store import get_store,StoredScan
from app.scan_store import ScanStore
from app.db.models import ScanSnapshot,Scan,Artifact,Finding,TrustScore,AgentExecution
from app.orchestration import run_full_scan_state


@pytest.mark.asyncio
async def test_tenant_api_isolation_including_pdf_and_history(tmp_path,monkeypatch):
    monkeypatch.setenv('GUARDIAN_TENANT_KEYS',json.dumps({'alpha':'a'*32,'beta':'b'*32}))
    monkeypatch.delenv('GUARDIAN_API_KEY',raising=False)
    monkeypatch.setenv('SECRET_DETECTION_URL','http://detector/analyze')
    async def detector(client,agent,url,artifact):
        from app.schemas import AgentResult
        return AgentResult(agent_name=agent,status='pass')
    monkeypatch.setattr('app.orchestration._request_detector',detector)
    store=ScanStore(f'sqlite+aiosqlite:///{tmp_path}/tenants.sqlite3')
    app.dependency_overrides[get_store]=lambda:store
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost') as api:
            headers_a={'Authorization':'Bearer '+'a'*32};headers_b={'Authorization':'Bearer '+'b'*32}
            response=await api.post('/analyze',headers=headers_a,json={'filename':'config.txt','content':'plain text'})
            assert response.status_code==200,response.text
            rid=response.json()['request_id']
            assert (await api.get('/scans/'+rid,headers=headers_b)).status_code==404
            assert (await api.get('/scans/'+rid+'/audit.pdf',headers=headers_b)).status_code==404
            assert (await api.get('/scans',headers=headers_b)).json()['items']==[]
            assert (await api.get('/scans/'+rid,headers=headers_a)).status_code==200
            assert (await api.get('/scans',headers=headers_a)).json()['items'][0]['request_id']==rid
            assert (await api.get('/scans/'+rid)).status_code==401
    finally:
        app.dependency_overrides.pop(get_store,None);await store.close()


@pytest.mark.asyncio
async def test_retention_deletes_final_children_and_preserves_pending(tmp_path,monkeypatch):
    monkeypatch.setenv('SECRET_DETECTION_URL','http://detector/analyze')
    async def detector(client,agent,url,artifact):
        from app.schemas import AgentResult
        return AgentResult(agent_name=agent,status='warn',findings=[{'category':'test','severity':'low','confidence':.5}])
    monkeypatch.setattr('app.orchestration._request_detector',detector)
    store=ScanStore(f'sqlite+aiosqlite:///{tmp_path}/retention.sqlite3')
    final=await run_full_scan_state({'filename':'config.txt','content':'plain'})
    pending=await run_full_scan_state({'filename':'second.txt','content':'plain'})
    await store.save(StoredScan(final));await store.save(StoredScan(pending))
    async with store.sessions.begin() as session:
        await session.execute(update(ScanSnapshot).values(updated_at=datetime.utcnow()-timedelta(days=40)))
        pending_id=await session.scalar(select(ScanSnapshot.scan_id).where(ScanSnapshot.request_id==pending['request_id']))
        await session.execute(update(Scan).where(Scan.id==pending_id).values(status='provisional'))
    assert await store.purge_expired(30)==1
    assert await store.load(final['request_id']) is None
    assert await store.load(pending['request_id']) is not None
    async with store.sessions() as session:
        for model in (Scan,Artifact,Finding,TrustScore,AgentExecution):
            assert await session.scalar(select(func.count()).select_from(model))==1
    await store.close()
