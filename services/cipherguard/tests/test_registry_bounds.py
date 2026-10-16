import asyncio
import logging
import httpx
import pytest
from app.registry.http_json import fetch

@pytest.mark.asyncio
@pytest.mark.parametrize('body,status,limit',[(b'{"ok":true}',200,100),(b'[]',500,100),(b'not json',500,100),(b'{"big":"'+b'x'*200+b'"}',500,100)])
async def test_streamed_registry_data_fails_closed_for_oversize_or_invalid_json(body,status,limit):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request:httpx.Response(200,content=body))) as client:
        actual,data=await fetch(client,'https://registry.npmjs.org/fixture',asyncio.Semaphore(1),logging.getLogger('test'),limit)
    assert actual==status
    if status==500:assert data=={}

@pytest.mark.asyncio
async def test_registry_redirect_is_not_followed():
    seen=[]
    def response(request):
        seen.append(str(request.url));return httpx.Response(302,headers={'Location':'http://127.0.0.1/private'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        status,data=await fetch(client,'https://registry.npmjs.org/fixture',asyncio.Semaphore(1),logging.getLogger('test'))
    assert status==500 and all(url.startswith('https://registry.npmjs.org/') for url in seen)
