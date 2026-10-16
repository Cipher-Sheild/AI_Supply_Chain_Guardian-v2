#!/usr/bin/env python3
"""Scan files before acceptance. Exit 0=Accept, 2=Review/threshold, 3=Reject, 4=error."""
import argparse
import json
import math
import os
from pathlib import Path
import sys
from guardian_http import request_json,wait_final

EXCLUDED_DIRS={'.git','.data','.venv','venv','node_modules','__pycache__','.pytest_cache','dist','.tools'}
SOURCE_EXTENSIONS={'.py','.js','.jsx','.ts','.tsx','.mjs','.cjs','.php','.java','.go','.md','.markdown'}
REVIEW_EXTENSIONS={'.rs','.c','.h','.cpp','.cc','.cxx','.hpp','.cs','.rb','.sh','.bash','.zsh','.kt','.kts','.swift','.scala','.lua','.dart','.r','.gradle','.csproj'}
MANIFEST_NAMES={'package.json','package-lock.json','npm-shrinkwrap.json','pyproject.toml','pipfile','requirements.txt','cargo.toml','cargo.lock','go.mod','go.sum','poetry.lock','uv.lock','.gitlab-ci.yml','.gitlab-ci.yaml','dockerfile','containerfile','compose.yml','compose.yaml','docker-compose.yml','docker-compose.yaml','license','licence','copying','license.txt','licence.txt','copying.txt','license.md','licence.md','copying.md'}


def discover(paths):
    output=[];seen=set()
    for path in paths:
        if not path.is_dir():candidates=[path]
        else:
            candidates=[]
            for directory,folders,names in os.walk(path,followlinks=False):
                folders[:]=sorted(name for name in folders if name not in EXCLUDED_DIRS)
                for name in sorted(names):
                    child=Path(directory)/name;lower=name.lower()
                    relative=child.as_posix()
                    if child.is_symlink():continue
                    if child.suffix.lower() in SOURCE_EXTENSIONS | REVIEW_EXTENSIONS or lower in MANIFEST_NAMES or lower.startswith('requirements') and lower.endswith('.txt') or '.github/workflows/' in relative:
                        candidates.append(child)
        for candidate in candidates:
            resolved=str(candidate.resolve())
            if resolved not in seen:output.append(candidate);seen.add(resolved)
            if len(output)>10000:raise ValueError('project scan exceeds 10000 supported files; scan subdirectories separately')
    return output


def deployment_config(path,tenant=None):
    if path.stat().st_size>65536:raise ValueError('deployment configuration too large')
    values={}
    for raw in path.read_text().splitlines():
        if raw.strip() and not raw.lstrip().startswith('#') and '=' in raw:
            key,value=raw.split('=',1);values[key.strip()]=value.strip()
    key=values.get('GUARDIAN_API_KEY','')
    if tenant:key=json.loads(values.get('GUARDIAN_TENANT_KEYS') or '{}').get(tenant,'')
    if not key:raise ValueError('selected deployment has no client API key')
    os.environ['GUARDIAN_API_KEY']=key

def exit_code(result,threshold):
    if result.get('scan_status')!='final': return 4
    score=result.get('trust_score')
    if isinstance(score,bool) or not isinstance(score,(int,float)) or not math.isfinite(score) or not 0<=score<=100: return 4
    recommendation=result.get('recommendation')
    if recommendation=='reject': return 3
    if recommendation!='accept' or score<threshold: return 2
    return 0

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files',nargs='+',type=Path)
    parser.add_argument('--url',default=os.getenv('GUARDIAN_URL','http://localhost:8000'))
    parser.add_argument('--threshold',type=float,default=80)
    parser.add_argument('--wait-seconds',type=float,default=240)
    parser.add_argument('--deployment-config',type=Path,help='Read client authentication from a local deployment configuration; never execute it.')
    parser.add_argument('--tenant',help='Select a key from GUARDIAN_TENANT_KEYS in deployment configuration.')
    parser.add_argument('--ca-file',type=Path,help='Additional trusted certificate for a local HTTPS demonstration.')
    parser.add_argument('--batch-size',type=int,default=4,help='Files per request, 1–50; bounded fan-out avoids detector queue saturation.')
    args=parser.parse_args(argv)
    if not 0<=args.threshold<=100 or args.wait_seconds<=0 or not 1<=args.batch_size<=50: parser.error('invalid threshold, wait-seconds, or batch-size')
    try:
        if args.deployment_config:deployment_config(args.deployment_config,args.tenant)
        if args.ca_file:os.environ['GUARDIAN_CA_FILE']=str(args.ca_file.resolve())
        paths=discover(args.files)
        if not paths:raise ValueError('no supported files discovered')
        files=[]
        results=[];size=0
        def submit(batch):
            result=request_json(args.url.rstrip('/')+'/analyze/batch',{'files':batch})
            results.append(wait_final(args.url,result,args.wait_seconds))
        for path in paths:
            if path.stat().st_size>262144: raise ValueError(f'{path}: exceeds 256 KiB limit')
            content=path.read_text(encoding='utf-8');length=len(content.encode('utf-8'))
            if files and (len(files)>=args.batch_size or size+length>1048576):submit(files);files=[];size=0
            files.append({'filename':str(path),'content':content});size+=length
        if files:submit(files)
        result=results[0] if len(results)==1 else {'files_scanned':len(paths),'scope':'source/configuration files under the supplied paths; unsupported formats remain Review',
            'aggregate_trust_score':min(item.get('trust_score',0) for item in results),'scans':results}
        print(json.dumps(result,indent=2))
        return max(exit_code(item,args.threshold) for item in results)
    except Exception as exc:
        print(f'Guardian scan failed: {type(exc).__name__}: {exc}',file=sys.stderr)
        return 4
if __name__=='__main__':sys.exit(main())
