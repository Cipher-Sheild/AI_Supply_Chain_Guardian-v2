import pytest
from fastapi.testclient import TestClient
from app import main
from app.schemas import Finding, Severity
from app.scanner import apply_language_weighting

@pytest.mark.parametrize("filename",["app.jsx","app.tsx","app.mjs","app.cjs","app.java","app.php"])
def test_capability_extensions_reach_scanner(monkeypatch,filename):
    calls=[]
    def scanner(content,path):
        calls.append(path)
        return [Finding(category="sql_injection",severity=Severity.high,confidence=.85,location=path+":1",remediation="Bind parameters")]
    monkeypatch.setattr(main,"run_semgrep",scanner)
    body=TestClient(main.app).post("/analyze",json={"filename":filename,"type":"code","content":"unsafe"}).json()
    assert calls==[filename] and body["status"]=="fail" and body["findings"][0]["severity"]=="high"

def test_rule_severity_preserved_for_js():
    assert apply_language_weighting(Severity.high,"javascript")==Severity.high

def test_go_has_no_clean_specialist_pass():
    body=TestClient(main.app).post("/analyze",json={"filename":"app.go","content":"package main\nfunc run(user string){db.Query(\"SELECT * FROM t WHERE id=\" + user)}"}).json()
    assert body['status']=='fail' and any(f['category']=='sql_injection' for f in body['findings'])

@pytest.mark.parametrize("filename",["app.jsx","app.tsx","app.mjs","app.cjs"])
def test_real_semgrep_scans_extended_js_suffixes(filename):
    from app.main import run_semgrep
    findings=run_semgrep('const result = eval(req.query.code);',filename)
    assert any(f.category=="unsafe_eval" and f.severity==Severity.high for f in findings)
