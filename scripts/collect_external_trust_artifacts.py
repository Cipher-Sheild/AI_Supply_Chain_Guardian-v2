#!/usr/bin/env python3
"""Collect inert, commit-pinned upstream artifacts and retain license notices.
No upstream code is imported, installed or executed. Labels await human review.
"""
import argparse,base64,hashlib,json,time,urllib.request
from pathlib import Path
CATALOG={
 'pypa/sampleproject':['src/sample/__init__.py','src/sample/simple.py','tests/test_simple.py','README.md'],
 'pallets/flask':['examples/tutorial/flaskr/__init__.py','examples/tutorial/flaskr/db.py','examples/tutorial/flaskr/auth.py','README.md'],
}
def get(url):
 request=urllib.request.Request(url,headers={'User-Agent':'Guardian-research-artifact-collector/1.0','Accept':'application/vnd.github+json'})
 with urllib.request.urlopen(request,timeout=30) as response:
  data=response.read(262145)
  if len(data)>262144:raise ValueError('External artifact exceeds size budget')
  return data

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
 rows=[];repos=[]
 for repo,paths in CATALOG.items():
  meta=json.loads(get('https://api.github.com/repos/'+repo));commit=json.loads(get('https://api.github.com/repos/'+repo+'/commits/'+meta['default_branch']))['sha']
  lic=json.loads(get('https://api.github.com/repos/'+repo+'/license?ref='+commit));spdx=lic['license']['spdx_id']
  if spdx not in {'MIT','BSD-3-Clause','Apache-2.0'}:raise ValueError('License requires manual clearance before collection')
  notice=base64.b64decode(lic['content']);license_path=lic['path'];license_url='https://raw.githubusercontent.com/'+repo+'/'+commit+'/'+license_path
  if get(license_url)!=notice:raise ValueError('Pinned license bytes differ from API response')
  directory=args.output/repo.replace('/','--');directory.mkdir()
  (directory/'UPSTREAM-LICENSE.txt').write_bytes(notice)
  repos.append({'repository':repo,'commit':commit,'spdx_api':spdx,'license_path':license_path,'license_url':license_url,'license_sha256':hashlib.sha256(notice).hexdigest(),'notice_retained':True,'checked_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'license_check_scope':'GitHub SPDX identification plus matching retained pinned license text; no legal opinion or whole dependency audit'})
  for path in paths+[license_path]:
   url='https://raw.githubusercontent.com/'+repo+'/'+commit+'/'+path;raw=get(url);destination=directory/path;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw)
   rows.append({'sample_id':repo.replace('/','--')+'--'+path.replace('/','--'),'path':str(destination.resolve()),'filename':Path(path).name,'label':'unreviewed','label_scope':'supplied_text','reviewer_id':'','independent_review':False,'human_reviewed':False,'sha256':hashlib.sha256(raw).hexdigest(),'repository':repo,'commit':commit,'source_url':url,'license_spdx':spdx,'license_notice':str((directory/'UPSTREAM-LICENSE.txt').resolve()),'evaluation_role':'external_unreviewed_not_training_or_accuracy_test'})
 (args.output/'manifest.json').write_text(json.dumps(rows,indent=2));(args.output/'provenance.json').write_text(json.dumps(repos,indent=2));print(f'Collected {len(rows)} pinned external files; labels unreviewed; no external code executed.')
if __name__=='__main__':main()
