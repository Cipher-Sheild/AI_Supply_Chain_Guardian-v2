import pytest
from app.outbox import Outbox

def test_jobs_and_resolved_results_survive_restart(tmp_path,monkeypatch):
    clock=[100.0];monkeypatch.setattr('app.outbox.time.time',lambda:clock[0])
    path=str(tmp_path/'queue.sqlite3')
    box=Outbox(path,max_entries=2)
    box.enqueue('cb',{'phase':'job','artifact':{'content':'test'}})
    assert Outbox(path).claim()[0]=='cb'
    assert box.claim() is None # leased work cannot be processed twice
    clock[0]+=241
    assert box.claim()[0]=='cb' # worker died; job recovers
    box.result('cb','http://engine/callback/cb',{'status':'error'})
    box.retry('cb');clock[0]+=100
    recovered=Outbox(path).claim()
    assert recovered[1]['phase']=='result'
    assert 'token' not in recovered[1]
    box.acknowledge('cb');assert box.claim() is None

def test_queue_capacity_is_bounded(tmp_path):
    import pytest
    box=Outbox(str(tmp_path/'q.sqlite3'),max_entries=1)
    box.enqueue('one',{'phase':'job'})
    with pytest.raises(RuntimeError): box.enqueue('two',{'phase':'job'})

def test_model_warmup_and_requests_load_only_once(monkeypatch):
    from app import embeddings
    from concurrent.futures import ThreadPoolExecutor
    import time
    calls=[];model=object()
    def load():
        calls.append(1);time.sleep(.01);return model
    monkeypatch.setattr(embeddings,'_model',None)
    monkeypatch.setattr(embeddings,'_model_load_failed',False)
    monkeypatch.setattr(embeddings,'_try_load_model',load)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results=list(executor.map(lambda _:embeddings.get_model(),range(8)))
    assert len(calls)==1 and all(item is model for item in results)

@__import__("pytest").mark.asyncio
async def test_span_work_limit_returns_unknown():
    import pytest
    from app.main import analyze
    from app.schemas import ArtifactRequest
    result=await analyze(ArtifactRequest(type='markdown',filename='readme.md',content='\n\n'.join(['Paragraph']*201)))
    assert result.status=='error' and result.coverage=='none' and result.unresolved

@__import__('pytest').mark.asyncio
async def test_openai_failure_closes_client_and_uses_explicit_budget(monkeypatch):
    from types import SimpleNamespace
    from app.llm_client import _call_openai
    import pytest
    calls={}
    class Client:
        def __init__(self,**settings):
            calls.update(settings)
            async def create(**kwargs):raise TimeoutError('provider unavailable')
            self.chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        async def __aenter__(self):return self
        async def __aexit__(self,*args):calls['closed']=True
    monkeypatch.setattr('openai.AsyncOpenAI',Client)
    monkeypatch.setenv('OPENAI_API_KEY','unit-test-only')
    with pytest.raises(TimeoutError):await _call_openai('test','')
    assert calls['closed'] and calls['timeout']==60 and calls['max_retries']==0

@pytest.mark.asyncio
async def test_redirect_is_not_acknowledged_as_callback_delivery(monkeypatch):
    import httpx
    from app import main
    from app.schemas import AgentResult
    original=httpx.AsyncClient
    calls=[]
    def handler(request):
        calls.append(request)
        return httpx.Response(307,headers={'Location':'https://example.invalid/other'})
    monkeypatch.setattr(main.httpx,'AsyncClient',lambda **kwargs:original(transport=httpx.MockTransport(handler),**kwargs))
    result=AgentResult(agent_name='prompt_injection',status='pass',callback_id='redirect-fixture')
    assert not await main._post_callback('http://guardian/callback/redirect-fixture',result,'synthetic-test-token')
    assert len(calls)==1


def test_callback_journal_does_not_follow_symlinks(tmp_path):
    import pytest
    from app.outbox import Outbox
    target=tmp_path/'unrelated';target.write_text('preserve me')
    link=tmp_path/'outbox.sqlite3';link.symlink_to(target)
    with pytest.raises(OSError):Outbox(str(link))
    assert target.read_text()=='preserve me'
