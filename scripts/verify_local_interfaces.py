#!/usr/bin/env python3
"""Actual HTTP batch/history/PDF/ML/failure-gate verification, no browser claims."""
import argparse,json,sys,urllib.request,urllib.error
from pathlib import Path
from guardian_http import request_json,wait_final
p=argparse.ArgumentParser();p.add_argument('--url',default='http://127.0.0.1:18508');p.add_argument('--output',type=Path,default=Path('docs/final-validation/interfaces-http.json'));a=p.parse_args()
clean=request_json(a.url+'/analyze/batch',{'files':[{'filename':'safe.py','content':'print(1)'},{'filename':'README.md','content':'# Project\n\nOrdinary public documentation.'}]});clean=wait_final(a.url,clean,240)
assert len(clean['per_file'])==2 and clean['scan_status']=='final'
saved=request_json(a.url+'/scans/'+clean['request_id']);assert saved==clean
history=request_json(a.url+'/scans?limit=3');assert history['items']
with urllib.request.urlopen(a.url+'/scans/'+clean['request_id']+'/audit.pdf',timeout=15) as response:pdf=response.read();assert pdf.startswith(b'%PDF')
secret=request_json(a.url+'/analyze',{'filename':'Dockerfile','content':'FROM alpine:3.20\nUSER 10001\nENV DATABASE_URL=postgresql://admin:FabricatedPasswordOnly@db/app\nENV GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n'})
assert secret['recommendation']=='reject'
assert 'FabricatedPasswordOnly' not in json.dumps(secret)
assert 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij' not in json.dumps(secret)
invalid=False
try:request_json(a.url+'/analyze/batch',{'files':[{'filename':'same.py','content':'print(1)'},{'filename':'same.py','content':'print(2)'}]})
except urllib.error.HTTPError as error:invalid=error.code==422
assert invalid
report={'url_port':a.url.rsplit(':',1)[-1],'batch_final':True,'history_retrieval_equal':True,'history_nonempty':True,'pdf_bytes':len(pdf),'credentials_masked':True,'secret_rejected':True,'duplicate_names_422':True,'scoring':clean.get('scoring',{}),'per_file_methods':[f.get('scoring',{}).get('method') for f in clean['per_file']]}
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print('HTTP batch/history/PDF/redaction/bounds checks passed.')
