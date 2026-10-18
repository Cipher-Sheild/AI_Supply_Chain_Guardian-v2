#!/usr/bin/env python3
"""Fresh hash-checked scans with explicit scope; labels never inferred from verdicts.

A reviewed holdout must pass --require-reviewed. Unreviewed developer fixtures
are permitted only as an explicitly documented development evaluation.
"""
import argparse,concurrent.futures,hashlib,json,sys,time
from urllib.error import HTTPError
from pathlib import Path
from guardian_http import request_json,wait_final
from guardian_cli import deployment_config

def validate_rows(manifest, require_reviewed=False):
 rows=json.loads(manifest.read_text());seen=set()
 if not isinstance(rows,list) or not rows:raise ValueError('Expected a nonempty manifest array')
 for row in rows:
  if row['sample_id'] in seen:raise ValueError('Duplicate sample ID')
  seen.add(row['sample_id'])
  if row.get('label') not in {'accept','review','reject','unreviewed'}:raise ValueError('Unknown label')
  if require_reviewed and (row.get('independent_review') is not True or not row.get('reviewer_id') or row.get('label')=='unreviewed'):
   raise ValueError('Independent review is incomplete')
  path=Path(row['path']);path=path if path.is_absolute() else manifest.parent/path
  raw=path.read_bytes()
  if len(raw)>262144 or hashlib.sha256(raw).hexdigest()!=row.get('sha256'):raise ValueError('Artifact size/hash mismatch')
 return rows

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('manifest',type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--url',required=True);p.add_argument('--deployment-config',type=Path,required=True);p.add_argument('--scan-scope',choices=['supplied_text','resolved_images'],required=True);p.add_argument('--workers',type=int,choices=range(1,5),default=2);p.add_argument('--require-reviewed',action='store_true');args=p.parse_args()
 rows=validate_rows(args.manifest,args.require_reviewed)
 if any(row.get('label_scope')!=args.scan_scope for row in rows):raise ValueError('Label scope and requested scan scope differ')
 deployment_config(args.deployment_config)
 health=request_json(args.url.rstrip('/')+'/health',timeout=15)
 if health.get('status')!='ok':raise ValueError('Evaluation readiness must be healthy before fresh collection')
 args.output.mkdir(parents=True,exist_ok=False)
 lock={'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest(),'scan_scope':args.scan_scope,'workers':args.workers,'review_required':args.require_reviewed,'endpoint':args.url,'scope_warning':'Text-only excludes resolved image contents; resolved-image results require separate labels.','count':len(rows),'health':health}
 (args.output/'run.json').write_text(json.dumps(lock,indent=2))
 def scan(row):
  path=Path(row['path']);path=path if path.is_absolute() else args.manifest.parent/path
  raw=path.read_bytes()
  if hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('Artifact changed after validation')
  payload={'filename':row.get('filename',path.name),'content':raw.decode('utf-8'),'options':{'scan_scope':args.scan_scope,'enable_hardening':False}}
  if row.get('artifact_type'):payload['artifact_type']=row['artifact_type']
  start=time.monotonic()
  for attempt in range(5):
   try:
    result=request_json(args.url.rstrip('/')+'/analyze',payload,timeout=90);break
   except HTTPError as exc:
    # Only this explicit admission rejection is safe to retry automatically:
    # no scan was admitted. Do not retry uncertain persistence/transport errors.
    body=exc.read(4096)
    if exc.code!=503 or b'scanner capacity exhausted' not in body or attempt==4:raise
    time.sleep(.25*(2**attempt))
  result=wait_final(args.url,result,240)
  return {'sample_id':row['sample_id'],'artifact_sha256':row['sha256'],'scan_scope':args.scan_scope,'seconds':round(time.monotonic()-start,3),'response':result}
 failures=[];completed=0
 with (args.output/'responses.jsonl').open('w') as f, concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
  futures={executor.submit(scan,row):row['sample_id'] for row in rows}
  for future in concurrent.futures.as_completed(futures):
   try:record=future.result();f.write(json.dumps(record)+'\n');f.flush()
   except Exception as exc:failures.append({'sample_id':futures[future],'error_type':type(exc).__name__,'http_status':getattr(exc,'code',None)})
   completed+=1
   if completed%20==0:print(f'{completed}/{len(rows)} finalized/submitted; failures {len(failures)}',flush=True)
 (args.output/'failures.json').write_text(json.dumps(failures,indent=2))
 print(f'Finished {len(rows)} artifacts; {len(failures)} failures. Labels unchanged.',flush=True)
 return bool(failures)
if __name__=='__main__':sys.exit(main())
