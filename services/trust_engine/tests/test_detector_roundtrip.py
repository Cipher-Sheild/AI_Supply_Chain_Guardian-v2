"""Import each standalone detector in its own process, then parse its actual wire schema."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
from app.contract import AgentResult

ROOT=Path(__file__).resolve().parents[3]

@pytest.mark.parametrize("service",["cipherguard","code_security","docker_security","secret_detection","workflow_cicd","license_compliance","prompt_injection"])
def test_all_detector_schemas_roundtrip_without_dropped_extensions(service):
    rich=service in {"cipherguard","docker_security","secret_detection"}
    module="app.schema" if service in {"cipherguard","docker_security"} else "app.schemas"
    data={"category":"test","severity":"high","confidence":.8,"reason":"Explain risk","remediation":"Fix risk"}
    if rich:
        data.update(detector_id="rule:1",file_path="artifact.txt",line_number=5,preview="masked preview")
        if service=="cipherguard":data.update(package="pkg",ecosystem="python",score=95,signals=["risk"],risk_contribution=95,recommendation="block")
        if service=="docker_security":data.update(hard_block=True,sources=["engine"],risk_contribution=95)
    else:data.update(location="artifact.txt:5",details={"nested":{"all":[1,{"retained":"yes"}]}})
    program=f'''import json
from {module} import Finding, AgentResult
finding=Finding(**{data!r})
result=AgentResult(agent_name={service!r},status="fail",findings=[finding],evidence={{"nested":{{"all":[1,{{"retained":"yes"}}]}}}})
print(result.model_dump_json())
'''
    environment={**os.environ,"PYTHONPATH":"."}
    process=subprocess.run([sys.executable,"-c",program],cwd=ROOT/'services'/service,env=environment,capture_output=True,text=True,timeout=20)
    assert process.returncode==0,process.stderr
    body=json.loads(process.stdout)
    parsed=AgentResult.model_validate(body).model_dump(mode="json")
    assert parsed==body
    finding=parsed["findings"][0]
    assert finding["reason"]==data["reason"] and finding["remediation"]==data["remediation"]
    assert finding["location"]=="artifact.txt:5"
    for key,value in data.items():
        if key in finding: assert finding[key]==value
        else:assert finding["details"][key]==value
    assert parsed["evidence"]["nested"]["all"][1]["retained"]=="yes"


def test_canonical_language_and_filename_cannot_be_spoofed_by_hint():
    from app.orchestration import canonical_request
    from app.routing import route_file
    decision=route_file('# comment',filename='app.py')
    payload=canonical_request({'file_path':'app.py','content':'# comment','language':'java'},decision)
    assert payload['filename']=='app.py' and payload['language']=='python'
    decision=route_file('Instructions',filename='README.md')
    assert canonical_request({'content':'Instructions','language':'python'},decision)['language']=='markdown'
