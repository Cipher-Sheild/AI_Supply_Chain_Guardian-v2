#!/usr/bin/env python3
"""Join independently supplied labels to server request IDs; never infer labels.
Manifest: CSV, JSON array, or JSONL with sample_id,path,label,artifact_type?
Relative artifact paths resolve against the manifest directory.
"""
import argparse
import hashlib
import os
import csv
import json
from pathlib import Path
import sys
from guardian_http import request_json,wait_final

def read_manifest(path):
    if path.suffix.lower()=='.csv':
        with path.open(newline='',encoding='utf-8') as stream: rows=list(csv.DictReader(stream))
    elif path.suffix.lower()=='.json': rows=json.loads(path.read_text())
    else: rows=[json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    if not isinstance(rows,list) or not rows: raise ValueError('manifest must contain samples')
    seen=set()
    for row in rows:
        if not isinstance(row,dict) or any(str(row.get(k,'')).strip()=='' or row.get(k) is None for k in ('sample_id','path','label')):
            raise ValueError('each sample requires sample_id, path and an independently assigned label')
        row['sample_id']=str(row['sample_id'])
        if row['sample_id'] in seen: raise ValueError('sample_id must be unique')
        seen.add(row['sample_id'])
    return rows

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest',type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--url',default='http://localhost:8000')
    parser.add_argument('--responses',type=Path,help='Optional final response JSONL; protects independently assigned labels')
    parser.add_argument('--deployment-config',type=Path)
    parser.add_argument('--ca-file',type=Path)
    parser.add_argument('--wait-seconds',type=float,default=240)
    args=parser.parse_args(argv)
    if args.wait_seconds<=0: parser.error('wait-seconds must be positive')
    if args.deployment_config:
        from guardian_cli import deployment_config
        deployment_config(args.deployment_config)
    if args.ca_file:os.environ['GUARDIAN_CA_FILE']=str(args.ca_file.resolve())
    rows=read_manifest(args.manifest);failed=0
    if args.responses:
        args.responses.parent.mkdir(parents=True,exist_ok=True)
        args.responses.write_text('')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=['sample_id','request_id','label','scan_status','error'],lineterminator='\n')
        writer.writeheader()
        for index,row in enumerate(rows):
            mapping={'sample_id':row['sample_id'],'label':row['label'],'request_id':'','scan_status':'error','error':''}
            try:
                path=Path(row['path'])
                if not path.is_absolute(): path=args.manifest.resolve().parent/path
                if path.stat().st_size>262144: raise ValueError('artifact exceeds 256 KiB work limit')
                payload={'content':path.read_text(encoding='utf-8'),'filename':path.name}
                if row.get('artifact_type'):payload['artifact_type']=row['artifact_type']
                result=request_json(args.url.rstrip('/')+'/analyze',payload)
                mapping['request_id']=result['request_id']
                result=wait_final(args.url,result,args.wait_seconds)
                mapping['scan_status']=result['scan_status']
                if args.responses:
                    with args.responses.open('a') as response_file: response_file.write(json.dumps({'sample_id':row['sample_id'],'artifact_sha256':hashlib.sha256(payload['content'].encode()).hexdigest(),'response':result})+'\n')
            except Exception as exc:
                mapping['error']=f'{type(exc).__name__}: {exc}';failed+=1
            writer.writerow(mapping);stream.flush()
            if (index+1)%20==0:print(f'Corpus {index+1}/{len(rows)}; errors {failed}',flush=True)
    print(f'{len(rows)} mappings written; {failed} submissions/finalizations failed. Labels preserved verbatim.')
    return 1 if failed else 0
if __name__=='__main__':sys.exit(main())
