import pytest
from httpx import AsyncClient, ASGITransport
from app import main
from app.contract import AgentResult

async def post(payload):
    async with AsyncClient(transport=ASGITransport(app=main.app),base_url="http://test") as client:
        return (await client.post("/analyze",json=payload)).json()

@pytest.mark.asyncio
@pytest.mark.parametrize("count",[1,9,21])
async def test_clean_dependencies_emit_evidence_not_findings(monkeypatch,count):
    async def registry(*args): return {"status":200,"exists":True,"published_versions":["1.0"]}
    monkeypatch.setattr(main,"run_existence_check",registry)
    monkeypatch.setattr(main,"get_min_edit_distance",lambda *args:(0,0))
    monkeypatch.setattr(main,"check_metadata_risk",lambda *args:[])
    monkeypatch.setattr(main,"calculate_score",lambda *args:0)
    body=await post({"filename":"requirements.txt","content":"\n".join(f"pkg{i}==1.0" for i in range(count))})
    assert body["status"]=="pass" and body["findings"]==[] and body["coverage"]=="full"
    assert len(body["evidence"]["packages"])==count
    AgentResult(**body)

@pytest.mark.asyncio
@pytest.mark.parametrize("registry_status,expected,floor",[(503,"error","review"),(404,"fail","reject")])
async def test_outage_distinct_from_nonexistent(monkeypatch,registry_status,expected,floor):
    async def registry(*args): return {"status":registry_status,"exists":False}
    monkeypatch.setattr(main,"run_existence_check",registry)
    monkeypatch.setattr(main,"get_min_edit_distance",lambda *args:(0,0))
    monkeypatch.setattr(main,"check_metadata_risk",lambda *args:[])
    monkeypatch.setattr(main,"calculate_score",lambda *args:100)
    body=await post({"filename":"C:\\repo\\requirements.txt","content":"unknownpkg==1"})
    assert body["status"]==expected and body["decision_floor"]==floor
    parsed=AgentResult(**body)
    if registry_status==404:
        assert parsed.findings[0].hard_block and parsed.findings[0].location=="C:\\repo\\requirements.txt:1"
        assert parsed.findings[0].details["package"]=="unknownpkg"
    else: assert parsed.findings==[] and body["evidence"]["packages"][0]["score"] is None

@pytest.mark.asyncio
@pytest.mark.parametrize("filename,content,status,coverage",[("package.json","{","error","none"),("requirements.txt","abc nonsense","error","none"),("package.json",'{"dependencies":{"local":"file:../x"}}',"warn","partial"),("package.json","{}","pass","full")])
async def test_manifest_integrity(filename,content,status,coverage):
    body=await post({"filename":filename,"content":content});assert body["status"]==status and body["coverage"]==coverage

@pytest.mark.asyncio
@pytest.mark.parametrize("name",["pypi_client","npm_client"])
async def test_registry_failure_never_cached(monkeypatch,name):
    from app.registry import pypi_client,npm_client
    module=pypi_client if name=="pypi_client" else npm_client
    writes=[]
    async def miss(*a):return None
    async def failure(*a):return 500,{}
    async def write(*a):writes.append(a)
    monkeypatch.setattr(module.cache,"get",miss);monkeypatch.setattr(module.cache,"set",write);monkeypatch.setattr(module,"_fetch_with_retries",failure)
    method=module.fetch_pypi_metadata if name=="pypi_client" else module.fetch_npm_metadata
    observation=await method("pkg",None)
    assert observation["status"]==500 and not writes
