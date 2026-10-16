import json
import pytest
import httpx
from app import advisories,main


@pytest.mark.asyncio
async def test_critical_advisory_preserves_reject_floor(monkeypatch):
    async def registry(*args):return {'status':200,'published_versions':['1.0.0'],'age_days':500,'maintainer_count':2}
    async def vulnerable(*args):return {'completed':True,'vulns':[{'id':'TEST-CRITICAL','severity':'critical','summary':'test advisory'}]}
    monkeypatch.setattr(main,'run_existence_check',registry)
    monkeypatch.setattr(main,'get_min_edit_distance',lambda *args:(0,0))
    monkeypatch.setattr(main,'lookup_advisories',vulnerable)
    result=await main.scan_manifest('requirements.txt','example==1.0.0')
    assert result.decision_floor=='reject' and any(f.category=='dependency_vulnerability' for f in result.findings)


@pytest.mark.asyncio
async def test_missing_feed_is_partial_not_clean(monkeypatch):
    async def registry(*args):return {'status':200,'published_versions':['1.0.0'],'age_days':500,'maintainer_count':2}
    async def unavailable(*args):return {'completed':False,'vulns':[],'error':'offline'}
    monkeypatch.setattr(main,'run_existence_check',registry)
    monkeypatch.setattr(main,'get_min_edit_distance',lambda *args:(0,0))
    monkeypatch.setattr(main,'lookup_advisories',unavailable)
    result=await main.scan_manifest('requirements.txt','example==1.0.0')
    assert result.coverage=='partial' and result.decision_floor=='review' and result.unresolved


@pytest.mark.asyncio
async def test_advisory_pagination_and_withdrawn_records():
    calls=[]
    def response(request):
        body=json.loads(request.content);calls.append(body)
        if 'page_token' not in body:return httpx.Response(200,json={'vulns':[{'id':'WITHDRAWN','withdrawn':'2026-01-01'}],'next_page_token':'second'})
        return httpx.Response(200,json={'vulns':[{'id':'VALID-HIGH','database_specific':{'severity':'HIGH'},'summary':'risk'}]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        result=await advisories.lookup(client,'python','pagination-test','1.0.0')
    assert result['completed'] and len(calls)==2 and [item['id'] for item in result['vulns']]==['VALID-HIGH']


def test_cvss_and_moderate_mapping():
    assert advisories.severity({'severity':[{'score':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]})=='critical'
    assert advisories.severity({'database_specific':{'severity':'MODERATE'}})=='medium'


def test_ranges_are_not_faked_as_exact_versions():
    assert advisories.exact_version('^1.0.0','javascript') is None
    assert advisories.exact_version('>=1.0','python') is None
    assert advisories.exact_version('==1.0','python')=='1.0'


@pytest.mark.asyncio
@pytest.mark.parametrize('ecosystem,requested,published',[('python','==1.0',['2.0']),('rust','=1.0.0',['2.0.0']),('go','v1.0.0',['v2.0.0'])])
async def test_missing_exact_versions_block_without_claiming_missing_package(monkeypatch,ecosystem,requested,published):
    async def registry(*args):return {'status':200,'published_versions':published,'age_days':500,'maintainer_count':2}
    monkeypatch.setattr(main,'run_existence_check',registry)
    monkeypatch.setattr(main,'get_min_edit_distance',lambda *args:(0,0))
    async with httpx.AsyncClient() as client:
        observation=await main.process_dependency(ecosystem,'example',requested,'manifest:1',client)
    assert observation['status']=='fail' and observation['finding'].hard_block
    assert 'exact version' in observation['finding'].recommendation


@pytest.mark.asyncio
async def test_python_equivalent_release_versions_are_accepted(monkeypatch):
    async def registry(*args):return {'status':200,'published_versions':['1.0.0'],'age_days':500,'maintainer_count':2}
    monkeypatch.setattr(main,'run_existence_check',registry)
    monkeypatch.setattr(main,'get_min_edit_distance',lambda *args:(0,0))
    async with httpx.AsyncClient() as client:
        observation=await main.process_dependency('python','example','==1.0','requirements.txt:1',client)
    assert observation['status']=='pass'


@pytest.mark.asyncio
async def test_go_proxy_escapes_uppercase_module_and_version():
    from app.registry_metadata import metadata
    paths=[]
    def respond(request):
        paths.append(request.url.path)
        return httpx.Response(200,json={'Version':'v1.2.3-RC1'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result=await metadata(client,'go','example.com/Team/pkg','v1.2.3-RC1')
    assert result['status']==200
    assert paths==['/example.com/!team/pkg/@v/v1.2.3-!r!c1.info']


@pytest.mark.asyncio
async def test_exact_version_without_release_inventory_is_incomplete(monkeypatch):
    async def registry(*args):return {'status':200,'age_days':500,'maintainer_count':2}
    monkeypatch.setattr(main,'run_existence_check',registry)
    async with httpx.AsyncClient() as client:
        observation=await main.process_dependency('python','example','==1.0','requirements.txt:1',client)
    assert observation['status']=='error' and observation['finding'] is None

@pytest.mark.asyncio
@pytest.mark.parametrize('http_status',[301,401,403,408,429,500,503])
async def test_registry_http_failures_cannot_become_clean_or_hallucination(monkeypatch,http_status):
    import app.main as main
    async def unavailable(*args,**kwargs):return {'status':http_status}
    monkeypatch.setattr(main,'run_existence_check',unavailable)
    async with httpx.AsyncClient() as client:
        observation=await main.process_dependency('python','example','==1.0','requirements.txt:1',client)
    assert observation['status']=='error'
    assert observation['score'] is None and observation['finding'] is None
    assert observation['registry_http_status']==http_status
