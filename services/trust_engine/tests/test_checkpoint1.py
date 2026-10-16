import importlib.util
import json
from pathlib import Path
import pytest
import httpx
from pydantic import ValidationError
from app.contract import AgentResult, Finding, ArtifactRequest
from app.routing import route_file
from app.state import AgentCallRecord
from app.fusion import fuse
from app.orchestration import canonical_request, _request_detector, DetectorCallError
from app.features import feature_event, append_feature_event

def state(filename="requirements.txt"):
    route=route_file("",filename)
    return {"request_id":"regression","routing":[route],"results":[AgentCallRecord(file=filename,agent=a,agent_ran=True,status="pass",result=AgentResult(agent_name=a,status="pass")) for a in route.expected_agents]}

@pytest.mark.parametrize("status",["stub","error","fail","pending"])
def test_expected_unusable_status_never_accepts(status):
    s=state();r=s["results"][0];r.status=status;r.result=AgentResult(agent_name=r.agent,status=status,callback_id="cb" if status=="pending" else None)
    assert fuse(s).recommendation == "review"

@pytest.mark.parametrize("mutation",["missing","no_result","partial","unresolved","license_review"])
def test_required_uncertainty_never_accepts(mutation):
    s=state();r=s["results"][1]
    if mutation=="missing": s["results"].pop(1)
    elif mutation=="no_result": r.result=None
    elif mutation=="partial": r.result.coverage="partial"
    elif mutation=="unresolved": r.result.unresolved=True
    else: r.result.findings=[Finding(category="license_review",severity="low",confidence=0)]
    assert fuse(s).recommendation == "review"

@pytest.mark.parametrize("kwargs",[{"hard_block":True},{"decision_floor":"reject"}])
def test_hard_override_survives_serialization_and_bypasses_model(kwargs):
    s=state("compose.yaml");r=s["results"][0]
    r.result=AgentResult.model_validate_json(AgentResult(agent_name=r.agent,status="fail",decision_floor=kwargs.get("decision_floor","accept"),findings=[Finding(category="container_escape",severity="critical",confidence=1,hard_block=kwargs.get("hard_block",False),location="compose.yaml:4",reason="Socket mount",remediation="Remove mount",details={"engine":{"id":"DSG"}})]).model_dump_json());r.status="fail"
    class NeverCalled:
        def score(self,*args): raise AssertionError("override must bypass the model")
    result=fuse(s,NeverCalled());assert result.recommendation=="reject" and result.trust_score==0
    assert result.detector_results[0].findings[0].remediation=="Remove mount"

@pytest.mark.parametrize("value",[-1,1.1,float("inf"),float("nan")])
def test_confidence_bounds(value):
    with pytest.raises(ValidationError): Finding(category="x",severity="low",confidence=value)

@pytest.mark.parametrize("value",[-1,101,float("inf"),float("nan")])
def test_score_bounds(value):
    with pytest.raises(ValidationError): Finding(category="x",severity="low",confidence=1,score=value)

@pytest.mark.parametrize("callback_id",[None,""," "])
def test_pending_identity_required(callback_id):
    with pytest.raises(ValidationError): AgentResult(agent_name="x",status="pending",callback_id=callback_id)

@pytest.mark.parametrize("filename,kind,agent",[("compose.yaml","compose","docker_security"),("docker-compose.yml","compose","docker_security"),("README.md","markdown","prompt_injection"),("Foo.java","code","code_security"),("a.php","code","code_security"),("x.jsx","code","code_security"),("x.tsx","code","code_security"),("x.mjs","code","code_security"),("x.cjs","code","code_security")])
def test_capability_routing(filename,kind,agent):
    decision=route_file("x",filename);assert decision.artifact_type==kind and agent in decision.expected_agents
    payload=canonical_request({"filename":filename,"content":"x","options":{"enable_cve_scan":True}},decision)
    assert ArtifactRequest(**payload).options["enable_cve_scan"] is True
    assert payload["type"]==payload["artifact_type"]==kind and payload["filename"]==filename

@pytest.mark.parametrize('filename',['pyproject.toml','Pipfile','Cargo.lock','go.mod'])
def test_extended_manifests_route_to_dependency_agents(filename):
    s=state(filename)
    assert set(s['routing'][0].expected_agents)=={'cipherguard','license_compliance','secret_detection'}

@pytest.mark.asyncio
async def test_mismatched_detector_identity_is_error():
    transport=httpx.MockTransport(lambda req:httpx.Response(200,json=AgentResult(agent_name="wrong",status="pass").model_dump()))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(DetectorCallError): await _request_detector(client,"cipherguard","http://test/analyze",{"content":""})

def test_feature_log_preserves_null_and_sanitizes(tmp_path,monkeypatch):
    s=state();r=s["results"][0];r.result.evidence={"packages":[{"package":"SENSITIVE","score":0}],"secret":"NEVER_LOG"};r.result.findings=[Finding(category="secret",severity="low",confidence=.2,reason="NEVER_LOG",details={"snippet":"NEVER_LOG"})]
    path=tmp_path/"features.jsonl";monkeypatch.setenv("FEATURE_LOG_PATH",str(path));s["trust_result"]=fuse(s).model_dump();append_feature_event(s)
    raw=path.read_text();assert "NEVER_LOG" not in raw and "SENSITIVE" not in raw
    event=json.loads(raw);agents=event["files"][0]["agents"]
    assert agents["code_security"] is None
    assert agents["cipherguard"]["agent_specific_scores"]["package_scores"]==[0]
    assert agents["cipherguard"]["severity_counts"]["low"]==1
    s["results"].pop(0);assert feature_event(s)["files"][0]["agents"]["cipherguard"] is None

def test_recursive_schema_audit_detects_nested_loss():
    script=Path(__file__).resolve().parents[3]/"evaluation/phase_a_schema_audit/audit.py"
    spec=importlib.util.spec_from_file_location("schema_audit",script);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    assert module.dropped_paths({"findings":[{"details":{"deep":{"lost":1}}}]},{"findings":[{"details":{"deep":{}}}]})==["/findings/0/details/deep/lost"]

def test_request_type_validation_uses_matrix():
    with pytest.raises(ValidationError): ArtifactRequest(content="",type="invalid")
    with pytest.raises(ValidationError): ArtifactRequest(content="",type="code",artifact_type="compose")

@pytest.mark.parametrize("count",[1,9,21])
def test_clean_package_observations_do_not_reduce_trust(count):
    s=state();s["results"][0].result.evidence={"packages":[{"score":0,"status":"pass"} for _ in range(count)]}
    result=fuse(s);assert result.recommendation=="accept" and result.trust_score==100

def test_scorer_cannot_accept_required_uncertainty():
    s=state();s["results"][0].status="error";s["results"][0].result=AgentResult(agent_name="cipherguard",status="error")
    class Optimistic:
        def score(self,*args):return 100
    assert fuse(s,Optimistic()).recommendation=="review"

def test_response_reports_achieved_coverage():
    from app.state import achieved_coverage
    s=state();assert achieved_coverage(s)=="full"
    s["results"][0].result=AgentResult(agent_name="cipherguard",status="error")
    assert achieved_coverage(s)=="none"


def test_filename_wins_over_manifest_content_sniff():
    decision=route_file("{}","requirements.txt")
    payload=canonical_request({"filename":"requirements.txt","content":"{}"},decision)
    assert payload["ecosystem"]=="python"

@pytest.mark.asyncio
async def test_dispatch_forwards_canonical_inferred_request(monkeypatch):
    from app import orchestration
    calls=[]
    async def request(client,agent,url,payload):
        calls.append((agent,payload));return AgentResult(agent_name=agent,status="pass")
    monkeypatch.setattr(orchestration,"_request_detector",request)
    for variable in orchestration.DETECTOR_URL_ENV_VARS.values():monkeypatch.setenv(variable,"http://test/analyze")
    s=await orchestration.run_full_scan_state({"filename":"compose.yaml","content":"services: {}","options":{"enable_cve_scan":True}})
    assert {name for name,_ in calls}=={"docker_security","secret_detection"}
    assert all(payload["type"]==payload["artifact_type"]=="compose" and payload["filename"]=="compose.yaml" and payload["options"]["enable_cve_scan"] is True for _,payload in calls)


@pytest.mark.parametrize('filename,content',[('Dockerfile','FROM alpine:3.20'),('compose.yaml','services: {}')])
def test_container_scans_enable_advisories_by_default(filename,content):
    decision=route_file(filename=filename,content=content)
    payload=canonical_request({'filename':filename,'content':content},decision)
    assert payload['options']['enable_cve_scan'] is True
    payload=canonical_request({'filename':filename,'content':content,'options':{'enable_cve_scan':False}},decision)
    assert payload['options']['enable_cve_scan'] is False
