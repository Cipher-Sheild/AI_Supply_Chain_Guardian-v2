from fastapi.testclient import TestClient
from app import main, readiness
from app.engines.native import NativeDockerLint
from app.engines.result import EngineResult


def test_native_lint_without_processes(monkeypatch):
    monkeypatch.setattr('subprocess.run',lambda *a,**k: (_ for _ in ()).throw(AssertionError('external scanner invoked')))
    result=NativeDockerLint().analyze('FROM alpine:3.20\nWORKDIR relative\nRUN apk add curl\nCMD echo hello\n')
    assert result.completed
    assert {f.detector_id for f in result.findings} == {'GDL001','GDL005','GDL007'}


def test_invalid_and_unsupported_syntax_not_clean():
    for content in ['FROM scratch\ninvalid-line','FROM scratch\nRUN <<EOF\necho hi\nEOF','FROM scratch\nBOGUS value']:
        assert not NativeDockerLint().analyze(content).completed


def test_native_health_does_not_require_scanner_binaries(monkeypatch,tmp_path):
    import time
    monkeypatch.delenv('GUARDIAN_EXTERNAL_SCANNERS',raising=False)
    monkeypatch.setattr(readiness,'_last',(time.monotonic(),{'rules_loaded':True,'docker_hub':True}))
    monkeypatch.setattr('shutil.which',lambda *a:None)
    monkeypatch.setenv('DOCKER_CALLBACK_OUTBOX_PATH',str(tmp_path/'jobs.sqlite3'))
    with TestClient(main.app) as client:response=client.get('/health')
    assert response.status_code == 200
    assert response.json()['checks']['guardian_native_lint']


def test_requested_cves_never_silently_clean(monkeypatch):
    monkeypatch.setattr(main.base_image_checker,'check_image_exists',lambda *a:EngineResult(True))
    response=TestClient(main.app).post('/analyze',json={'filename':'Dockerfile',
        'content':'FROM alpine:3.20\nUSER 10001\n','options':{'enable_cve_scan':True,'enable_hardening':False}}).json()
    assert response['evidence']['scanner_backend']=='guardian_native'
    assert response['coverage']=='partial' and response['unresolved']
    assert response['decision_floor']=='review'


def test_compose_images_use_native_job_queue(monkeypatch):
    from app import image_jobs
    queued=[]
    def enqueue(images,path,base):
        queued.extend(images);return 'job-test'
    monkeypatch.setattr(image_jobs,'enqueue',enqueue)
    body=TestClient(main.app).post('/analyze',json={'filename':'compose.yaml',
        'content':'services:\n  app:\n    image: alpine:3.20\n',
        'options':{'enable_cve_scan':True}}).json()
    assert body['status']=='pending' and body['callback_id']=='job-test'
    assert queued[0]['reference']=='alpine:3.20'


def test_compose_build_without_image_is_incomplete_when_cves_requested():
    body=TestClient(main.app).post('/analyze',json={'filename':'compose.yaml',
        'content':'services:\n  app:\n    build: .\n',
        'options':{'enable_cve_scan':True}}).json()
    assert body['coverage']=='partial' and body['decision_floor']=='review'
