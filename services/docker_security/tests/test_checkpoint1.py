import subprocess
import urllib.error
import pytest
from fastapi.testclient import TestClient
from app import main
from app.schema import Finding, AgentResult
from app.contract import AgentResult as PortableResult
from app.engines.result import EngineResult
from app.engines.hadolint import HadolintEngine
from app.engines.trivy_config import TrivyConfigEngine
from app.engines.trivy_image import TrivyImageEngine
from app.registry.image_check import BaseImageChecker
from app.parsing import DockerfileParser
from app.harden import DockerfileHardener
from app.cache import cache_instance

@pytest.mark.parametrize("engine,method,args",[(HadolintEngine,"analyze",("FROM scratch",)),(TrivyConfigEngine,"analyze",("FROM scratch",)),(TrivyImageEngine,"scan_image",("test-image:1234",))])
@pytest.mark.parametrize("failure",[FileNotFoundError(),subprocess.TimeoutExpired("scanner",1)])
def test_engine_failure_has_completion_metadata(monkeypatch,engine,method,args,failure):
    monkeypatch.setattr("subprocess.run",lambda *a,**k:(_ for _ in ()).throw(failure))
    monkeypatch.setattr(cache_instance,"get",lambda *a:None)
    result=getattr(engine(),method)(*args)
    assert not result.completed and result.error_reason and result.duration_ms>=0

@pytest.mark.parametrize("reference,base,tag",[("registry.example:5000/team/app:1","registry.example:5000/team/app","1"),("ubuntu@sha256:"+"a"*64,"ubuntu","sha256:"+"a"*64),("ubuntu:22@sha256:"+"b"*64,"ubuntu","sha256:"+"b"*64)])
def test_image_reference_parser(reference,base,tag):
    stage=DockerfileParser("FROM "+reference).stages[0]
    assert stage.base_image==base and stage.base_image_tag==tag and stage.image_ref==reference

def test_prior_alias_is_not_registry_image():
    parser=DockerfileParser("FROM alpine:3 AS build\nRUN echo hi\nFROM build\n")
    assert parser.stages[1].is_stage_alias

def test_registry_failure_not_cached_as_exists(monkeypatch):
    writes=[];monkeypatch.setattr(cache_instance,"get",lambda *a:None);monkeypatch.setattr(cache_instance,"set",lambda *a,**k:writes.append(a))
    monkeypatch.setattr("urllib.request.urlopen",lambda *a,**k:(_ for _ in ()).throw(TimeoutError()))
    result=BaseImageChecker().check_image_exists("ubuntu","22")
    assert not result.completed and writes==[]

def test_external_registry_and_digest_are_unverified(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen",lambda *a,**k:pytest.fail("must not call Hub for an external registry/digest"))
    checker=BaseImageChecker()
    assert not checker.check_image_exists("registry.example:5000/app:1", "").completed
    assert not checker.check_image_exists("ubuntu@sha256:"+"a"*64, "").completed

def test_image_404_blocks_and_preserves_fields(monkeypatch):
    monkeypatch.setattr(cache_instance,"get",lambda *a:None);monkeypatch.setattr(cache_instance,"set",lambda *a,**k:None)
    monkeypatch.setattr("urllib.request.urlopen",lambda *a,**k:(_ for _ in ()).throw(urllib.error.HTTPError("test",404,"missing",None,None)))
    result=BaseImageChecker().check_image_exists("missing-image","1",3,"Dockerfile.test")
    parsed=PortableResult(**AgentResult(status="fail",findings=result.findings).model_dump())
    assert result.completed and parsed.findings[0].hard_block
    assert parsed.findings[0].location=="Dockerfile.test:3" and parsed.findings[0].details["detector_id"]=="DSG-D012"

def test_missing_tools_readiness_degraded(monkeypatch):
    monkeypatch.setenv('GUARDIAN_EXTERNAL_SCANNERS','true')
    monkeypatch.setattr(main.shutil,"which",lambda *a:None)
    response=TestClient(main.app).get("/health")
    assert response.status_code==503 and response.json()["status"]=="degraded"

@pytest.mark.parametrize("content,path",[("FROM scratch\n","Dockerfile"),("services:\n  app:\n    image: alpine:3\n","compose.yaml")])
def test_missing_engine_degrades_coverage(monkeypatch,content,path):
    monkeypatch.setattr(main.hadolint_engine,"analyze",lambda *a:EngineResult(False,"missing"))
    monkeypatch.setattr(main.trivy_config_engine,"analyze",lambda *a:EngineResult(False,"missing"))
    monkeypatch.setattr(main.base_image_checker,"check_image_exists",lambda *a:EngineResult(True))
    body=TestClient(main.app).post("/analyze",json={"filename":path,"content":content,"options":{"enable_hardening":False}}).json()
    assert body["coverage"]=="partial" and body["unresolved"] and body["decision_floor"]=="review"
    assert not any("trivy_image" in engine for engine in body["evidence"]["engines_executed"])

def test_escape_block_survives_failed_tool(monkeypatch):
    monkeypatch.setattr(main.trivy_config_engine,"analyze",lambda *a:EngineResult(False,"missing"))
    body=TestClient(main.app).post("/analyze",json={"filename":"compose.yaml","content":"services:\n  app:\n    image: alpine:3\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"}).json()
    parsed=PortableResult(**body)
    assert parsed.decision_floor=="reject" and any(f.hard_block for f in parsed.findings)

@pytest.mark.parametrize("base",["scratch","gcr.io/distroless/static:nonroot"])
def test_no_shell_commands_added_for_shell_less_images(base):
    class Lint:
        def analyze(self,*args):return EngineResult(False,"missing")
    output=DockerfileHardener(Lint()).harden("FROM "+base+"\nCOPY app /app\nCMD [\"/app\"]",0)
    assert "useradd" not in output.hardened and "adduser" not in output.hardened
    assert not output.verification_passed and not output.lint_completed

def test_final_stage_last_user_and_alpine():
    class Lint:
        def analyze(self,*args):return EngineResult(True)
    output=DockerfileHardener(Lint()).harden('FROM ubuntu AS build\nCMD ["builder"]\nFROM alpine:3\nUSER app\nUSER root\nCMD ["app"]',0)
    before,after=output.hardened.split("FROM alpine:3")
    assert "adduser" not in before and "adduser -S" in after and after.rstrip().endswith("USER appuser")
    assert not output.verification_passed and not output.lint_improved
    assert "HEALTHCHECK" not in output.hardened and ":stable" not in output.hardened

@pytest.mark.parametrize("engine,method,args",[(HadolintEngine,"analyze",("FROM scratch",)),(TrivyConfigEngine,"analyze",("FROM scratch",)),(TrivyImageEngine,"scan_image",("test-image:1",))])
def test_invalid_scanner_output_is_not_clean(monkeypatch,engine,method,args):
    monkeypatch.setattr(cache_instance,"get",lambda *a:None)
    monkeypatch.setattr("subprocess.run",lambda *a,**k:subprocess.CompletedProcess(a,0,b'{}',b''))
    result=getattr(engine(),method)(*args);assert not result.completed


def test_stage_alias_does_not_trigger_registry_lookup(monkeypatch):
    checked=[]
    monkeypatch.setattr(main.hadolint_engine,"analyze",lambda *a:EngineResult(True))
    monkeypatch.setattr(main.trivy_config_engine,"analyze",lambda *a:EngineResult(True))
    def checker(image,*args): checked.append(image);return EngineResult(True)
    monkeypatch.setattr(main.base_image_checker,"check_image_exists",checker)
    body=TestClient(main.app).post("/analyze",json={"filename":"Dockerfile","content":"FROM alpine:3 AS builder\nFROM builder\nUSER app","options":{"enable_hardening":False}}).json()
    assert checked==["alpine:3"] and body["coverage"]=="full"
