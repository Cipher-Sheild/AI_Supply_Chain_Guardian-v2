import pytest,httpx
from httpx import AsyncClient,ASGITransport
from app.main import app
from app.engines.oci_inventory import retry_transient

@pytest.mark.asyncio
async def test_supplied_text_never_fetches_image(monkeypatch):
 from app import main
 monkeypatch.setattr(main.base_image_checker,'check_image_exists',lambda *a:pytest.fail('No image request in text scope'))
 async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
  r=await client.post('/analyze',json={'filename':'Dockerfile','content':'FROM debian:bookworm-slim\nUSER 10001\nHEALTHCHECK CMD true\n','options':{'scan_scope':'supplied_text','enable_cve_scan':True,'enable_hardening':False}})
 assert r.status_code==200
 x=r.json();assert x['coverage']=='full' and x['status']=='pass'
 assert x['evidence']['scan_scope']=='supplied_text'
 assert 'image_check:0' not in x['evidence']['engines_executed']

@pytest.mark.asyncio
@pytest.mark.parametrize("scope",["pretend_everything_clean",[],None,False])
async def test_invalid_scope_is_validation_error(scope):
 async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
  r=await client.post('/analyze',json={'content':'FROM scratch','options':{'scan_scope':scope}})
 assert r.status_code==422

@pytest.mark.asyncio
@pytest.mark.parametrize('status',[429,500,502,503,504])
async def test_transient_status_retries_bounded(status,monkeypatch):
 calls=[]
 async def op():
  calls.append(1)
  r=httpx.Response(status if len(calls)<3 else 200,request=httpx.Request('GET','https://example.invalid/'))
  r.raise_for_status();return b'ok'
 async def no_sleep(*a):pass
 monkeypatch.setattr('app.engines.oci_inventory.asyncio.sleep',no_sleep)
 assert await retry_transient(op)==b'ok' and len(calls)==3

@pytest.mark.asyncio
@pytest.mark.parametrize('status',[401,403,404])
async def test_permanent_failure_not_retried(status):
 calls=[]
 async def op():
  calls.append(1);httpx.Response(status,request=httpx.Request('GET','https://example.invalid/')).raise_for_status()
 with pytest.raises(httpx.HTTPStatusError):await retry_transient(op)
 assert len(calls)==1

@pytest.mark.asyncio
async def test_transport_failure_not_reported_clean(monkeypatch):
 calls=[]
 async def op():calls.append(1);raise httpx.ReadTimeout('network unavailable')
 async def no_sleep(*a):pass
 monkeypatch.setattr('app.engines.oci_inventory.asyncio.sleep',no_sleep)
 with pytest.raises(httpx.ReadTimeout):await retry_transient(op)
 assert len(calls)==3
