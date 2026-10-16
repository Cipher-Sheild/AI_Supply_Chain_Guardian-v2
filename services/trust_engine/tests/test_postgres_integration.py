"""Requires a migrated scratch database; CI provisions one separately."""
import asyncio
import os
from uuid import uuid4
import pytest
from sqlalchemy import select,delete
from app.scan_store import ScanStore
from app.pending_store import StoredScan,now_ms
from app.schemas import AgentResult
from app.lifecycle import apply_callback
from app.db.models import ScanSnapshot,Scan,AgentExecution,Finding,TrustScore,Artifact

@pytest.mark.asyncio
async def test_postgres_restart_and_distributed_row_lock(monkeypatch):
    url=os.getenv('TEST_DATABASE_URL')
    if not url:pytest.skip('requires migrated TEST_DATABASE_URL scratch database')
    from app.orchestration import _compiled_graph
    for name in ('SECRET_DETECTION','PROMPT_INJECTION'):monkeypatch.setenv(name+'_URL','http://detector/analyze')
    async def result(client,agent,url,artifact):
        return AgentResult(agent_name=agent,status='pending',callback_id=uuid4().hex) if agent=='prompt_injection' else AgentResult(agent_name=agent,status='pass')
    monkeypatch.setattr('app.orchestration._request_detector',result)
    state=await _compiled_graph.ainvoke({'files':[{'content':'hello','filename':'a.md'},{'content':'hello','filename':'b.md'}],'results':[],'routing_notes':[],'pending_callbacks':[]})
    state['trust_result']['trust_score']=93.75
    first=ScanStore(url);await first.seed()
    second=ScanStore(url)
    try:
        await first.save(StoredScan(state,{p.callback_id:now_ms() for p in state['pending_callbacks']}))
        assert (await second.load(state['request_id'])).state['trust_result']['trust_score']==93.75
        callbacks=list(state['pending_callbacks'])
        assert await second.request_id_for_callback(callbacks[0].callback_id)==state['request_id']
        async def update(store,cb):
            async with store.locked(state['request_id']) as stored:
                apply_callback(stored,cb.callback_id,AgentResult(agent_name='prompt_injection',status='pass'))
                await asyncio.sleep(.02)
        await asyncio.gather(update(first,callbacks[0]),update(second,callbacks[1]))
        assert not (await second.load(state['request_id'])).state['pending_callbacks']
    finally:
        async with first.sessions.begin() as session:
            row=await session.get(ScanSnapshot,state['request_id'])
            if row:
                scan=await session.get(Scan,row.scan_id)
                for model in (Finding,AgentExecution,TrustScore): await session.execute(delete(model).where(model.scan_id==row.scan_id))
                await session.delete(row);await session.flush()
                await session.delete(scan);await session.flush()
                await session.execute(delete(Artifact).where(Artifact.id==scan.artifact_id))
        await first.close();await second.close()
