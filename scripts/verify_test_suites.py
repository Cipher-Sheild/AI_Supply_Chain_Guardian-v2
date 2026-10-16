"""Run isolated component suites and retain machine-readable verification evidence."""
import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SERVICES=('code_security','docker_security','secret_detection','workflow_cicd','license_compliance','cipherguard','prompt_injection','trust_engine')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'evaluation/production-pass/unit-suite-latest.json')
    args=parser.parse_args();logs=ROOT/'.data/production-pass';logs.mkdir(parents=True,exist_ok=True)
    def run(name):
        cwd=ROOT/'services'/name if name!='utilities' else ROOT
        cmd=[sys.executable,'-m','pytest','-q']+(['scripts/tests'] if name=='utilities' else [])
        start=time.monotonic();log=logs/f'latest-{name}-tests.log'
        with log.open('w') as stream:result=subprocess.run(cmd,cwd=cwd,stdout=stream,stderr=subprocess.STDOUT)
        content=log.read_text();counts={key:sum(int(value) for value in re.findall(r'(\d+) '+key+r'\b',content.splitlines()[-1] if content.splitlines() else '')) for key in ('passed','failed','skipped','errors')}
        return {'component':name,'returncode':result.returncode,**counts,'seconds':round(time.monotonic()-start,2),'log':str(log.relative_to(ROOT))}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(run,(*SERVICES,'utilities')))
    report={'suites':results,'all_passed':all(result['returncode']==0 for result in results),'passed':sum(result['passed'] for result in results),'skipped':sum(result['skipped'] for result in results),'scope':'Local isolated unit/regression suites; not proof of security production readiness'}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));return 0 if report['all_passed'] else 1
if __name__=='__main__':raise SystemExit(main())
