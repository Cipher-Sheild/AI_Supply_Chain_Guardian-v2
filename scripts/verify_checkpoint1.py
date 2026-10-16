"""Run all eight service suites independently; their app package names overlap.
Usage: /path/to/test-venv/bin/python scripts/verify_checkpoint1.py
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ['trust_engine','cipherguard','license_compliance','prompt_injection','code_security','docker_security','secret_detection','workflow_cicd']

def main():
    output=ROOT/os.getenv('VERIFY_OUTPUT_DIR','docs/checkpoint-1');output.mkdir(parents=True,exist_ok=True)
    environment=dict(os.environ,PATH=str(Path(sys.executable).parent)+os.pathsep+os.environ['PATH'],PYTHONPATH='.')
    selected = sys.argv[1:] or SERVICES
    if any(service not in SERVICES for service in selected): raise SystemExit("Unknown service")
    previous = output / "test-results.json"
    results = json.loads(previous.read_text()) if selected != SERVICES and previous.exists() else {}
    for service in selected:
        started=time.perf_counter()
        process=subprocess.Popen([sys.executable,'-m','pytest','tests','-q'],cwd=ROOT/'services'/service,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            log,_=process.communicate(timeout=int(os.getenv("VERIFY_SUITE_TIMEOUT_SECONDS","300")))
            code=process.returncode
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(process.pid,signal.SIGKILL)
            log,_=process.communicate()
            code='timeout'
        text=log.decode('utf-8',errors='replace')
        (output/f'{service}-tests.txt').write_text('\n'.join(line.rstrip() for line in text.splitlines())+'\n')
        results[service]={'exit_code':code,'elapsed_seconds':round(time.perf_counter()-started,2),'summary':next((line for line in reversed(text.splitlines()) if 'passed' in line or 'failed' in line or 'error' in line),'no test summary')}
        print(service,results[service],flush=True)
    (output/'test-results.json').write_text(json.dumps(results,indent=2)+'\n')
    return 0 if all(result['exit_code']==0 for result in results.values()) else 1

if __name__=='__main__':sys.exit(main())
