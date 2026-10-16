"""Start eight isolated host processes and preserve real HTTP/schema evidence.
Artifact fixtures are smoke inputs, not labeled training data. The judge is
deliberately disabled; embedding/ScanCode availability is reported honestly.
"""
import json,os,subprocess,time,urllib.request,urllib.error,signal,sys,importlib.util,tempfile,socket,argparse
from pathlib import Path
r=Path(__file__).resolve().parents[1];python=sys.executable
parser=argparse.ArgumentParser(description='Controlled host HTTP smoke; not Compose/PostgreSQL/model validation.')
parser.add_argument('--output-dir',type=Path,default=r/'docs/checkpoint-2')
parser.add_argument('--port-base',type=int,default=18101)
parser.add_argument('--database-url',default='')
parser.add_argument('--redis-url',default='redis://127.0.0.1:1/0')
parser.add_argument('--corpus-manifest',type=Path)
parser.add_argument('--live-models',action='store_true',help='Use cached embeddings and local Ollama instead of deliberately disabled judge')
parser.add_argument('--ollama-model',default='llama3.2:latest')
args=parser.parse_args()
if not 1024<=args.port_base<=65527:parser.error('port-base must be 1024–65527')
scratch=tempfile.TemporaryDirectory(prefix='guardian-http-smoke-')
out=args.output_dir.resolve();out.mkdir(parents=True,exist_ok=True)
(out/'host-smoke-features.jsonl').write_text('')
names=['cipherguard','code_security','secret_detection','docker_security','workflow_cicd','license_compliance','prompt_injection','trust_engine']
env=dict(os.environ,PYTHONPATH='.',PATH=str(Path(python).parent)+os.pathsep+os.environ['PATH'],
    DATABASE_URL=args.database_url or 'sqlite+aiosqlite:///'+scratch.name+'/scans.sqlite3',REDIS_URL=args.redis_url,
    CALLBACK_TOKEN='host-smoke-token-not-a-secret',FEATURE_LOG_PATH=str(out/'host-smoke-features.jsonl'),
    CALLBACK_OUTBOX_PATH=scratch.name+'/outbox.sqlite3',LLM_PROVIDER='ollama',OLLAMA_HOST='http://127.0.0.1:1',OPENAI_API_KEY='',HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
env['TRUST_SCORER']=os.getenv('TRUST_SCORER','weighted')
if args.live_models:env.update(OLLAMA_HOST='http://127.0.0.1:11434',OLLAMA_MODEL=args.ollama_model,OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',TOKENIZERS_PARALLELISM='false')
for i,name in enumerate(names):env[name.upper()+'_URL']=f'http://127.0.0.1:{args.port_base+i}/analyze'
env['TRUST_ENGINE_CALLBACK_URL']=f'http://127.0.0.1:{args.port_base+7}/callback/{{callback_id}}'
processes=[]
def get(url):
 try:
  with urllib.request.urlopen(url,timeout=5) as response:return response.status,json.load(response)
 except urllib.error.HTTPError as e:return e.code,json.load(e)
def post(url,payload):
 with urllib.request.urlopen(urllib.request.Request(url,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'}),timeout=11) as response:return json.load(response)
try:
 for i,name in enumerate(names):
  with socket.socket() as sock:
   sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
   sock.bind(('127.0.0.1',args.port_base+i))
 for i,name in enumerate(names):
  handle=open('/tmp/guardian-host-'+name+'.log','w')
  processes.append((subprocess.Popen([python,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(args.port_base+i)],cwd=r/'services'/name,env=env,stdout=handle,stderr=subprocess.STDOUT,start_new_session=True),handle))
 for i,name in enumerate(names):
  for attempt in range(60):
   if processes[i][0].poll() is not None: raise RuntimeError(name+' exited; inspect /tmp/guardian-host-'+name+'.log')
   try:
    with urllib.request.urlopen(f'http://127.0.0.1:{args.port_base+i}/openapi.json',timeout=1):pass
    break
   except Exception:time.sleep(.25)
  else:raise RuntimeError(name+' process failed to start')
 print('Eight local HTTP processes started; waiting for real Semgrep warm-up.',flush=True)
 start=time.monotonic()
 while time.monotonic()-start<100:
  status,data=get(f'http://127.0.0.1:{args.port_base+1}/health')
  if status==200:break
  time.sleep(1)
 print('Semgrep readiness:',status,flush=True)
 if args.live_models:
  start=time.monotonic()
  while time.monotonic()-start<90:
   status,data=get(f'http://127.0.0.1:{args.port_base+6}/health')
   if status==200:break
   time.sleep(1)
  print('Prompt model readiness:',status,flush=True)
 artifacts={
 'code':{'filename':'app.py','content':'print(1)','type':'code'},
 'dependency':{'filename':'requirements.txt','content':'requests==2.31.0','type':'dependency'},
 'dockerfile':{'filename':'Dockerfile','content':'FROM alpine:3.20\nUSER root\n','type':'dockerfile'},
 'compose':{'filename':'compose.yml','content':'services:\n  web:\n    image: alpine:3.20\n    privileged: true\n','type':'compose'},
 'workflow':{'filename':'deploy.yml','content':'on: push\njobs:\n  job:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n','type':'workflow'},
 'markdown':{'filename':'README.md','content':'Hello team.','type':'markdown'},
 'unknown':{'filename':'settings.cfg','content':'setting=true'},
 }
 report={'deployment':'host HTTP processes, not Compose','storage':'PostgreSQL' if args.database_url.startswith('postgresql') else 'SQLite, not PostgreSQL','readiness':{},'scans':{},'schema_audit':{}}
 for i,name in enumerate(names):
  status,data=get(f'http://127.0.0.1:{args.port_base+i}/health');report['readiness'][name]={'http_status':status,**data}
 for kind,payload in artifacts.items():
  started=time.monotonic();body=post(f'http://127.0.0.1:{args.port_base+7}/analyze',payload)
  report['scans'][kind]={'request_id':body['request_id'],'trust_score':body['trust_score'],'recommendation':body['recommendation'],'scan_status':body['scan_status'],'coverage':body['routing']['overall_coverage'],'initial_ms':round((time.monotonic()-started)*1000,2),'agents':{a['agent_name']:{'status':a['status'],'coverage':a['coverage']} for a in body['detector_results']}}
  status,saved=get(f'http://127.0.0.1:{args.port_base+7}/scans/'+body['request_id']);assert saved==body
  print(kind,report['scans'][kind]['recommendation'],report['scans'][kind]['coverage'],flush=True)
 # Nested schema audit against real detector HTTP responses; no mocked transport.
 os.environ.update({name.upper()+'_URL':env[name.upper()+'_URL'] for name in names})
 sys.path.insert(0,str(r/'services/trust_engine'))
 spec=importlib.util.spec_from_file_location('audit',r/'evaluation/phase_a_schema_audit/audit.py');audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
 for name,payload in audit.ARTIFACTS.items():
  report['schema_audit'][name]=audit.audit(name,payload)
 (out/'host-smoke.json').write_text(json.dumps(report,indent=2)+'\n')
 print('Saved host HTTP smoke evidence.',flush=True)
 if args.corpus_manifest:
  result=subprocess.run([python,str(r/'scripts/run_labeled_corpus.py'),str(args.corpus_manifest),'--output',str(out/'corpus-mapping.csv'),'--responses',str(out/'corpus-responses.jsonl'),'--url',f'http://127.0.0.1:{args.port_base+7}','--wait-seconds','200'],env=env)
  if result.returncode:raise RuntimeError('corpus contains submission/finalization failures; inspect mapping')
 report['final_readiness']={}
 for i,name in enumerate(names):
  status,data=get(f'http://127.0.0.1:{args.port_base+i}/health');report['final_readiness'][name]={'http_status':status,**data}
 (out/'host-smoke.json').write_text(json.dumps(report,indent=2)+'\n')
finally:
 for process,handle in processes:
  try:os.killpg(process.pid,signal.SIGTERM)
  except ProcessLookupError:pass
 for process,handle in processes:
  try:process.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL)
  handle.close()

 scratch.cleanup()
