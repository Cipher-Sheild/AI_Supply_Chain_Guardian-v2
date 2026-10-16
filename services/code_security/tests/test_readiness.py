import pytest
from app import main

@pytest.mark.asyncio
async def test_failed_warmup_never_reports_ready(monkeypatch):
    def broken(*args): raise RuntimeError('missing engine')
    monkeypatch.setattr(main, 'run_semgrep', broken)
    monkeypatch.setattr(main, '_ready', False)
    await main._warm_up_semgrep()
    await main._warm_task
    assert (await main.health()).status_code == 503

@pytest.mark.asyncio
async def test_real_warmup_checks_findings(monkeypatch):
    monkeypatch.setattr(main, 'run_semgrep', lambda *args: [object()])
    monkeypatch.setattr(main, '_ready', False)
    await main._warm_up_semgrep()
    await main._warm_task
    assert (await main.health()).status_code == 200

def test_request_timeout_is_capped_but_cold_warmup_can_use_90_seconds(monkeypatch):
    import json
    from types import SimpleNamespace
    from app import scanner
    timeouts=[]
    def run(*args,**kwargs):
        timeouts.append(kwargs['timeout'])
        return SimpleNamespace(stdout=json.dumps({'results':[]}),stderr='',returncode=0)
    monkeypatch.setenv('SEMGREP_TIMEOUT_SECONDS','60')
    monkeypatch.setattr(scanner,'_resolve_semgrep_binary',lambda:'semgrep')
    monkeypatch.setattr(scanner,'_run_bounded',run)
    scanner.run_semgrep('print(1)','x.py')
    scanner.run_semgrep('print(1)','x.py',90)
    assert timeouts==[7.5,90]


def test_timeout_terminates_native_child_processes(tmp_path):
    import os,sys,time,subprocess
    from app.scanner import _run_bounded
    pidfile=tmp_path/'child.pid'
    code="import subprocess,sys,time; from pathlib import Path; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);Path(sys.argv[1]).write_text(str(child.pid));time.sleep(30)"
    with pytest.raises(subprocess.TimeoutExpired):
        _run_bounded([sys.executable,'-c',code,str(pidfile)],cwd=str(tmp_path),timeout=.5)
    pid=int(pidfile.read_text())
    for _ in range(20):
        stat=__import__('pathlib').Path(f'/proc/{pid}/stat')
        try:
            if not stat.exists() or stat.read_text().split()[2]=='Z':break
        except OSError:break
        time.sleep(.05)
    else:raise AssertionError('timed-out scanner left running child')


def test_incomplete_fragment_does_not_claim_full_coverage():
    from fastapi.testclient import TestClient
    response=TestClient(main.app).post('/analyze',json={'filename':'fragment.py','content':'print(1)\ndef broken('})
    assert response.status_code==200
    body=response.json()
    assert body['coverage'] in {'partial','none'} and body['unresolved']
