import json
import pytest
import httpx
from app import image_jobs
from app.contract import AgentResult
from app.schema import Finding
from app.engines.result import EngineResult


def configure(monkeypatch,tmp_path):
    monkeypatch.setenv('DOCKER_CALLBACK_OUTBOX_PATH',str(tmp_path/'jobs.sqlite3'))
    monkeypatch.setenv('TRUST_ENGINE_CALLBACK_URL','http://callback/callback/{callback_id}')
    monkeypatch.setenv('CALLBACK_TOKEN','private-callback-token')


def test_job_does_not_persist_callback_token(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    callback=image_jobs.enqueue([{'reference':'alpine:3.20','line':1}],'Dockerfile',AgentResult(agent_name='docker_security',status='pass').model_dump())
    connection=image_jobs.connect()
    try:
        payload=connection.execute('SELECT payload FROM jobs WHERE id=?',(callback,)).fetchone()[0]
        assert 'private-callback-token' not in payload
    finally:connection.close()


@pytest.mark.asyncio
async def test_completed_critical_result_retries_redirect_without_ack(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    callback=image_jobs.enqueue([{'reference':'alpine:3.20','line':1}],'Dockerfile',AgentResult(agent_name='docker_security',status='pass',evidence={}).model_dump())
    async def image(*args):
        finding=Finding(detector_id='TEST-CVE',file_path='Dockerfile',line_number=1,preview='package',confidence=1,severity='critical',reason='test',remediation='upgrade',hard_block=True,category='cve_vulnerability')
        return EngineResult(True,findings=[finding]),{'image_ref':'alpine:3.20','manifest_digest':'sha256:'+'a'*64,'platform':'linux/amd64','os_release':{},'layers_verified':1,'packages':[{}],'package_inventory_scope':'OS packages'}
    monkeypatch.setattr(image_jobs,'analyze_image',image)
    original_client=httpx.AsyncClient;delivered=[]
    def response(request):
        delivered.append(json.loads(request.content));return httpx.Response(302,headers={'location':'http://wrong-host/'})
    monkeypatch.setattr(image_jobs.httpx,'AsyncClient',lambda **kwargs:original_client(transport=httpx.MockTransport(response),**kwargs))
    await image_jobs.process(*image_jobs.claim())
    assert delivered[0]['decision_floor']=='reject'
    assert delivered[0]['evidence']['total_findings']==1
    assert delivered[0]['evidence']['severity']=='critical'
    assert delivered[0]['evidence']['risk_score']==100
    connection=image_jobs.connect()
    try:
        row=connection.execute('SELECT payload,attempts FROM jobs WHERE id=?',(callback,)).fetchone()
        assert row and json.loads(row[0])['phase']=='result' and row[1]==1
    finally:connection.close()


def test_journal_symlink_refused(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    target=tmp_path/'unrelated';target.write_text('preserve me')
    (tmp_path/'jobs.sqlite3').symlink_to(target)
    with pytest.raises(OSError):image_jobs.connect()
    assert target.read_text()=='preserve me'


@pytest.mark.asyncio
async def test_registry_http_failure_is_review_with_safe_status_evidence(monkeypatch,tmp_path):
    configure(monkeypatch,tmp_path)
    image_jobs.enqueue([{'reference':'alpine:3.20','line':1}],'Dockerfile',AgentResult(agent_name='docker_security',status='pass',evidence={}).model_dump())
    async def unavailable(*args):
        raise httpx.HTTPStatusError('registry unavailable',request=httpx.Request('GET','https://registry-1.docker.io/'),response=httpx.Response(429))
    monkeypatch.setattr(image_jobs,'analyze_image',unavailable)
    real_client=httpx.AsyncClient;delivered=[]
    def accept(request):
        delivered.append(json.loads(request.content));return httpx.Response(200)
    monkeypatch.setattr(image_jobs.httpx,'AsyncClient',lambda **kwargs:real_client(transport=httpx.MockTransport(accept),**kwargs))
    await image_jobs.process(*image_jobs.claim())
    result=delivered[0]
    assert result['decision_floor']=='review' and result['unresolved']
    assert result['evidence']['native_image_http_status']==429
    assert 'private-callback-token' not in json.dumps(result)
