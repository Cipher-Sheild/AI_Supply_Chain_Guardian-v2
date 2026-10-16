#!/usr/bin/env python3
"""Run all eight services locally with explicit bounded configuration.
Requires dependencies/tools installed in --python; does not modify permissions.
"""
import argparse,os,secrets,signal,socket,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SERVICES=['cipherguard','code_security','secret_detection','docker_security','workflow_cicd','license_compliance','prompt_injection','trust_engine']
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python',default=os.sys.executable)
    parser.add_argument('--port-base',type=int,default=18101)
    parser.add_argument('--database-url',default='')
    parser.add_argument('--redis-url',default='redis://127.0.0.1:6379/0')
    parser.add_argument('--ollama-host',default='http://127.0.0.1:11434')
    parser.add_argument('--ollama-model',default='guardian-judge')
    parser.add_argument('--judge-provider',choices=['local','ollama','openai','grok','groq'],default='ollama')
    parser.add_argument('--scorer',choices=['weighted','ml'],default='weighted')
    parser.add_argument('--state-dir',type=Path,default=ROOT/'.data')
    parser.add_argument('--dashboard',action='store_true')
    args=parser.parse_args()
    args.python=str(Path(args.python).resolve())
    if not 1024<=args.port_base<=65527:parser.error('invalid port-base')
    data=args.state_dir.resolve();data.mkdir(parents=True,exist_ok=True);data.chmod(0o700)
    env=dict(os.environ,PYTHONPATH='.',PATH=str(ROOT/'.tools/bin')+os.pathsep+str(Path(args.python).resolve().parent)+os.pathsep+os.environ['PATH'],
        DATABASE_URL=args.database_url or 'sqlite+aiosqlite:///'+str(data/'scans.sqlite3'),REDIS_URL=args.redis_url,
        CALLBACK_TOKEN=os.getenv('CALLBACK_TOKEN') or secrets.token_urlsafe(32),FEATURE_LOG_PATH=str(data/'features.jsonl'),
        CALLBACK_OUTBOX_PATH=str(data/'prompt-outbox.sqlite3'),LLM_PROVIDER=args.judge_provider,OLLAMA_HOST=args.ollama_host,OLLAMA_MODEL=args.ollama_model,
        DOCKER_CALLBACK_OUTBOX_PATH=str(data/'docker-outbox.sqlite3'),
        TRUST_SCORER=args.scorer,TRUST_MODEL_PATH=str(ROOT/'services/trust_engine/models/guardian.json'),OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',TOKENIZERS_PARALLELISM='false')
    for i,name in enumerate(SERVICES):env[name.upper()+'_URL']=f'http://127.0.0.1:{args.port_base+i}/analyze'
    env['TRUST_ENGINE_CALLBACK_URL']=f'http://127.0.0.1:{args.port_base+7}/callback/{{callback_id}}'
    env['TRUST_ENGINE_URL']=f'http://127.0.0.1:{args.port_base+7}'
    children=[]
    try:
        for i in range(8):
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.bind(('127.0.0.1',args.port_base+i))
        for i,name in enumerate(SERVICES):
            log=(data/f'{name}.log').open('a')
            process=subprocess.Popen([args.python,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(args.port_base+i)],cwd=ROOT/'services'/name,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            children.append((process,log))
        if args.dashboard:
            log=(data/'frontend.log').open('a');children.append((subprocess.Popen(['npm','run','dev','--','--host','127.0.0.1','--port','3000','--strictPort'],cwd=ROOT/'frontend',env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True),log))
        print(f'Trust Engine: http://127.0.0.1:{args.port_base+7}; logs: {data}; Ctrl-C stops this stack.',flush=True)
        if args.dashboard:print('Dashboard: http://127.0.0.1:3000',flush=True)
        while True:
            for process,_ in children:
                if process.poll() is not None:raise RuntimeError('service exited; inspect private .data logs')
            time.sleep(1)
    except KeyboardInterrupt:pass
    finally:
        for process,_ in children:
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
        for process,log in children:
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait()
            log.close()
if __name__=='__main__':main()
