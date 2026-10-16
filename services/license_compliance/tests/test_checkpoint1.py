import pytest
from app.license_lookup import normalize_license_text, _tree_for, LicenseResult, _run_scancode_fallback
from app.license_expression import parse_expression
from app.extraction import Dependency, extract_dependencies
from app.conflict_engine import evaluate_all, fuse
from app.policy import Policy
from app.contract import AgentResult

def result(expression):
    ids,op,unknown=normalize_license_text([expression])
    return LicenseResult(spdx_expressions=ids,expression_op=op,expression_tree=_tree_for(ids,op),source="registry_field",confidence=.9,warnings=unknown)

@pytest.mark.parametrize("expression,expected",[("MIT AND UnknownLicense","needs_review"),("MIT OR UnknownLicense","needs_review"),("MIT AND GPL-3.0-only","conflict"),("MIT OR GPL-3.0-only","compliant"),("MIT AND (Apache-2.0 OR GPL-3.0-only)","compliant"),("(MIT OR Apache-2.0) AND GPL-3.0-only","conflict"),("MIT WITH UnknownException","needs_review"),("MIT AND (GPL-3.0-only","needs_review")])
def test_complete_license_expression(expression,expected):
    dep=Dependency("pkg","1","python");verdict=evaluate_all([dep],{"python:pkg:1":result(expression)},Policy())[0]
    assert verdict.verdict==expected
    output=AgentResult(agent_name="license_compliance",**fuse([verdict]))
    if expected=="needs_review": assert output.unresolved and output.decision_floor=="review"
    if expected=="conflict":
        assert output.decision_floor=="review"
        assert not any(f.hard_block for f in output.findings)

def test_unknown_zero_confidence_is_unresolved():
    dep=Dependency("pkg","1","python");v=evaluate_all([dep],{"python:pkg:1":LicenseResult(confidence=0)},Policy())
    assert fuse(v)["decision_floor"]=="review"

def test_scancode_tree_not_flattened(monkeypatch):
    monkeypatch.setattr("app.license_lookup._scancode_get_licenses",lambda path:{"license_detections":[{"license_expression_spdx":"MIT AND UnknownLicense"}],"percentage_of_license_text":100})
    ids,op,conf,unknown=_run_scancode_fallback("license text")
    assert "UnknownLicense" in unknown
    assert _tree_for(ids,op)["op"]=="AND"

@pytest.mark.parametrize("filename,content",[("requirements.txt","foo == definitely not a version"),("package.json","{"),("package.json",'{"dependencies":[]}'),("package.json",'{"dependencies":{"x":9}}')])
def test_malformed_manifests_are_errors(filename,content):
    with pytest.raises(ValueError): extract_dependencies({"filename":filename,"content":content})

@pytest.mark.parametrize("filename,content",[("package.json",'{"dependencies":{"x":"workspace:*"}}'),("requirements.txt","-r other.txt")])
def test_unsupported_only_manifest_not_clean(filename,content):
    dependencies,skipped=extract_dependencies({"filename":filename,"content":content});assert not dependencies and skipped

def test_empty_valid_manifest_is_clean():
    assert extract_dependencies({"filename":"package.json","content":"{}"})==([],[])

def test_license_findings_preserve_manifest_location_and_tree():
    dependencies,_=extract_dependencies({"filename":"requirements.txt","content":"# dependencies\npkg==1"})
    verdict=evaluate_all(dependencies,{"python:pkg:1":result("MIT AND UnknownLicense")},Policy())
    output=AgentResult(agent_name="license_compliance",**fuse(verdict))
    finding=output.findings[0]
    assert finding.location=="requirements.txt:2" and finding.reason and finding.remediation
    assert finding.details["expression_tree"]["op"]=="AND"


def test_explicit_denylist_rejects():
    policy=Policy(denied_licenses=["GPL-3.0-only"])
    dep=Dependency("pkg","1","python")
    verdict=evaluate_all([dep],{"python:pkg:1":result("GPL-3.0-only")},policy)[0]
    output=AgentResult(agent_name="license_compliance",**fuse([verdict]))
    assert output.decision_floor=="reject" and output.findings[0].hard_block

@pytest.mark.parametrize('expression,denied,floor',[
    ('GPL-3.0-only AND MIT',['MIT'],'reject'),
    ('AGPL-3.0-only',['AGPL-*'],'reject'),
    ('GPL-3.0-only OR MIT',['MIT'],'review'),
    ('GPL-3.0-only OR AGPL-3.0-only',['GPL-*','AGPL-*'],'reject'),
])
def test_explicit_denylist_expression_semantics(expression,denied,floor):
    dep=Dependency('pkg','1','python')
    output=AgentResult(agent_name='license_compliance',**fuse(evaluate_all([dep],{'python:pkg:1':result(expression)},Policy(denied_licenses=denied,always_flag=['AGPL-3.0-only']))))
    assert output.decision_floor==floor

def test_shipped_policy_has_no_implicit_organization_denylist():
    from app.main import _policy
    for expression in ('GPL-3.0-only','AGPL-3.0-only'):
        dep=Dependency('pkg','1','python')
        output=AgentResult(agent_name='license_compliance',**fuse(evaluate_all([dep],{'python:pkg:1':result(expression)},_policy)))
        assert output.decision_floor=='review'
        assert not any(f.hard_block for f in output.findings)
