import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4
import pytest
from sqlalchemy import select, func
from app.scan_store import ScanStore
from app.db.models import Finding, AgentExecution, TrustScore
from app.pending_store import StoredScan, now_ms
from app.orchestration import run_full_scan_state
from app.schemas import AgentResult
from app.lifecycle import finalize_overdue, apply_callback

@pytest.mark.asyncio
async def test_persist_final_fractional_score_and_normalized_records(tmp_path,monkeypatch):
    monkeypatch.setenv('SECRET_DETECTION_URL','http://secret/analyze')
    async def result(*args):
        return AgentResult(agent_name=args[1],status='warn',findings=[{'category':'example','severity':'low','confidence':.5}])
    monkeypatch.setattr('app.orchestration._request_detector',result)
    state=await run_full_scan_state({'content':'value','filename':'settings.txt'})
    state['trust_result']['trust_score']=92.75
    url=f'sqlite+aiosqlite:///{tmp_path}/scans.sqlite3'
    store=ScanStore(url);await store.save(StoredScan(state))
    assert (tmp_path/'scans.sqlite3').stat().st_mode & 0o777 == 0o600
    rid=state['request_id'];assert (await store.load(rid)).state['trust_result']['trust_score']==92.75
    async with store.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(Finding))==1
        assert await session.scalar(select(func.count()).select_from(AgentExecution))==1
        assert await session.scalar(select(TrustScore.overall_score))==92.75
    await store.close()
    reopened=ScanStore(url)
    assert (await reopened.load(rid)).state['request_id']==rid
    assert (await reopened.history(1,0))['items'][0]['request_id']==rid
    assert (await reopened.history(1,1))['items']==[]
    await reopened.close()

@pytest.mark.asyncio
async def test_overdue_pending_is_final_review_and_late_pass_cannot_change_it(tmp_path,monkeypatch):
    for name in ('CODE_SECURITY','SECRET_DETECTION','PROMPT_INJECTION'): monkeypatch.setenv(name+'_URL','http://detector/analyze')
    async def result(client,agent,url,artifact):
        return AgentResult(agent_name=agent,status='pending',callback_id='late') if agent=='prompt_injection' else AgentResult(agent_name=agent,status='pass')
    monkeypatch.setattr('app.orchestration._request_detector',result)
    state=await run_full_scan_state({'content':'print(1)','filename':'code.py'})
    stored=StoredScan(state,pending_since={'late':now_ms()-181000})
    assert finalize_overdue(stored)
    assert not stored.state['pending_callbacks']
    assert stored.state['trust_result']['recommendation']=='review'
    assert not apply_callback(stored,'late',AgentResult(agent_name='prompt_injection',status='pass'))

@pytest.mark.asyncio
async def test_concurrent_database_updates_do_not_lose_results(tmp_path,monkeypatch):
    from app.orchestration import _compiled_graph
    for name in ('SECRET_DETECTION','PROMPT_INJECTION'): monkeypatch.setenv(name+'_URL','http://detector/analyze')
    async def result(client,agent,url,artifact):
        return AgentResult(agent_name=agent,status='pending',callback_id=artifact['filename']) if agent=='prompt_injection' else AgentResult(agent_name=agent,status='pass')
    monkeypatch.setattr('app.orchestration._request_detector',result)
    state=await _compiled_graph.ainvoke({'files':[{'content':'#test','filename':'a.md'},{'content':'#test','filename':'b.md'}],'results':[],'routing_notes':[],'pending_callbacks':[]})
    store=ScanStore(f'sqlite+aiosqlite:///{tmp_path}/atomic.sqlite3')
    await store.save(StoredScan(state,{p.callback_id:now_ms() for p in state['pending_callbacks']}))
    async def update(cb):
        async with store.locked(state['request_id']) as stored:
            apply_callback(stored,cb,AgentResult(agent_name='prompt_injection',status='pass'))
    await asyncio.gather(update('a.md'),update('b.md'))
    assert not (await store.load(state['request_id'])).state['pending_callbacks']
    await store.close()

def test_alembic_offline_generates_sql_without_database_connection(tmp_path):
    env=dict(os.environ,DATABASE_URL='postgresql+asyncpg://example:example@not-a-host/unused')
    res=subprocess.run([sys.executable,'-m','alembic','upgrade','head','--sql'],capture_output=True,text=True,env=env)
    assert res.returncode==0,res.stderr
    assert 'CREATE TABLE scan_snapshots' in res.stdout
    assert 'ALTER TABLE trust_scores ALTER COLUMN overall_score TYPE FLOAT' in res.stdout

@pytest.mark.asyncio
async def test_batch_per_file_history_pdf_and_bounds(tmp_path,monkeypatch):
    from httpx import AsyncClient,ASGITransport
    from app.main import app
    from app.pending_store import get_store
    for name in ('CODE_SECURITY','SECRET_DETECTION','PROMPT_INJECTION'): monkeypatch.setenv(name+'_URL','http://detector/analyze')
    async def result(client,agent,url,artifact):
        return AgentResult(agent_name=agent,status='pass')
    monkeypatch.setattr('app.orchestration._request_detector',result)
    store=ScanStore(f'sqlite+aiosqlite:///{tmp_path}/api.sqlite3')
    app.dependency_overrides[get_store]=lambda:store
    try:
        async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
            response=await client.post('/analyze/batch',json={'files':[{'filename':'a.py','content':'print(1)'},{'filename':'readme.md','content':'Hello'}]})
            assert response.status_code==200,response.text
            body=response.json();assert len(body['per_file'])==2
            assert (await client.get('/scans/'+body['request_id'])).json()==body
            history=(await client.get('/scans?limit=1')).json()
            assert history['items'][0]['request_id']==body['request_id']
            pdf=await client.get('/scans/'+body['request_id']+'/audit.pdf')
            assert pdf.status_code==200 and pdf.content.startswith(b'%PDF')
            assert (await client.post('/analyze/batch',json={'files':[]})).status_code==422
            assert (await client.post('/analyze/batch',json={'files':[{'filename':'a','content':'x'}]*2})).status_code==422
            assert (await client.post('/analyze',json={'content':'x'*262145})).status_code==413
            assert (await client.post('/analyze',content=b'x'*2097153,headers={'Content-Type':'application/json'})).status_code==413
    finally:
        app.dependency_overrides.pop(get_store,None);await store.close()

@pytest.mark.asyncio
async def test_global_dispatch_deadline_includes_queue(monkeypatch):
    from app import orchestration
    monkeypatch.setenv('SECRET_DETECTION_URL','http://detector/analyze')
    monkeypatch.setattr(orchestration,'SCAN_DEADLINE_SECONDS',.02)
    semaphore=asyncio.Semaphore(1);await semaphore.acquire()
    monkeypatch.setattr(orchestration,'_GLOBAL_CALLS',semaphore)
    state=await run_full_scan_state({'filename':'settings.txt','content':'test'})
    assert state['trust_result']['recommendation']=='review'
    assert 'deadline' in state['results'][0].error_reason
    assert not state['results'][0].agent_ran

@pytest.mark.asyncio
async def test_history_does_not_rescore_per_file_with_a_changed_model(tmp_path,monkeypatch):
    from httpx import AsyncClient,ASGITransport
    from app.main import app
    from app.pending_store import get_store
    async def clean(client,agent,url,artifact):return AgentResult(agent_name=agent,status='pass')
    monkeypatch.setattr('app.orchestration._request_detector',clean)
    store=ScanStore(f'sqlite+aiosqlite:///{tmp_path}/historical.sqlite3')
    app.dependency_overrides[get_store]=lambda:store
    try:
        async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
            initial=await client.post('/analyze',json={'filename':'settings.cfg','content':'hello'})
            assert initial.status_code==200,initial.text
            def broken(*args):raise AssertionError('stored per-file outcomes must not be rescored on read')
            monkeypatch.setattr('app.interfaces.fuse',broken)
            saved=await client.get('/scans/'+initial.json()['request_id'])
            assert saved.status_code==200 and saved.json()==initial.json()
    finally:
        app.dependency_overrides.pop(get_store,None);await store.close()

@pytest.mark.asyncio
async def test_cancelled_request_retains_worker_slot_until_thread_finishes(monkeypatch):
    import threading
    from app import runtime
    slots=asyncio.Semaphore(1);monkeypatch.setattr(runtime,'_slots',slots)
    started=threading.Event();release=threading.Event()
    def work():
        started.set();release.wait(timeout=2);return 1
    task=asyncio.create_task(runtime.bounded_work(work))
    try:
        await asyncio.to_thread(started.wait,1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        assert slots.locked()
        with pytest.raises(TimeoutError):await runtime.bounded_work(lambda:2)
    finally:release.set()
    for _ in range(100):
        if not slots.locked():break
        await asyncio.sleep(.005)
    assert await runtime.bounded_work(lambda:3)==3
