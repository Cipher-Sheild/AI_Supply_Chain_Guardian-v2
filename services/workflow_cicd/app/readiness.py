"""Bounded readiness probes; external failures remain explicit."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import time
import httpx
from fastapi.responses import JSONResponse
_last = (0, {})
async def readiness(service):
    global _last
    if time.monotonic() - _last[0] < 10:
        checks = dict(_last[1])
    else:
        checks = {'rules_loaded': True}
        try:
            for path in list((Path(__file__).parent/'data').glob('*.json')) + list((Path(__file__).parent/'rules').glob('*.json')):
                json.loads(path.read_text())
        except (OSError, ValueError): checks['rules_loaded'] = False
        targets = {}
        headers = {}
        if service in {'cipherguard', 'license_compliance'}:
            targets = {'pypi':'https://pypi.org/pypi/pip/json','npm':'https://registry.npmjs.org/npm'}
        if service == 'license_compliance':
            if os.getenv('GUARDIAN_EXTERNAL_SCANNERS','false').lower()=='true':
                from app.license_lookup import _scancode_get_licenses
                checks['scancode_fallback'] = _scancode_get_licenses is not None
            else:
                from app.native_license import templates
                try:checks['guardian_license_data']=bool(templates())
                except (OSError,ValueError):checks['guardian_license_data']=False
        if service == 'docker_security':
            targets = {'docker_hub':'https://hub.docker.com/v2/repositories/library/alpine/tags/latest/'}
        if service == 'prompt_injection':
            from app import embeddings
            from app.outbox import get_outbox
            checks['embedding_model'] = embeddings._model is not None
            if os.getenv('PROMPT_CLASSIFIER_ENABLED','true').lower()=='true':
                from app.semantic_classifier import load
                try:load();checks['semantic_classifier']=True
                except ValueError:checks['semantic_classifier']=False
            try:
                with get_outbox().connect() as conn:
                    checks['callback_journal'] = conn.execute('SELECT count(*) FROM outbox').fetchone()[0] < 64
            except Exception: checks['callback_journal'] = False
            provider = os.getenv('LLM_PROVIDER','ollama')
            checks['judge_configured'] = bool(os.getenv('GROQ_API_KEY') and os.getenv('GROQ_MODEL')) if provider=='groq' else bool(os.getenv('XAI_API_KEY') and os.getenv('XAI_MODEL')) if provider=='grok' else bool(os.getenv('OPENAI_API_KEY')) if provider == 'openai' else provider in {'ollama','local'}
            if provider=='local':
                from app.local_judge import ready
                checks['judge_model']=ready()
            if provider=='groq' and checks['judge_configured']:
                targets['judge_backend']='https://api.groq.com/openai/v1/models'
                headers['judge_backend']={'Authorization':'Bearer '+os.environ['GROQ_API_KEY']}
            if provider=='grok' and checks['judge_configured']:
                targets['judge_backend']='https://api.x.ai/v1/models'
                headers['judge_backend']={'Authorization':'Bearer '+os.environ['XAI_API_KEY']}
            if provider == 'ollama':
                from app.llm_client import _resolve_ollama_host
                targets['judge_backend'] = _resolve_ollama_host().rstrip('/')+'/api/tags'
            elif provider == 'openai' and checks['judge_configured']:
                targets['judge_backend'] = 'https://api.openai.com/v1/models/'+os.getenv('OPENAI_MODEL','gpt-4o-mini')
                headers['judge_backend'] = {'Authorization':'Bearer '+os.environ['OPENAI_API_KEY']}
        async with httpx.AsyncClient(timeout=0.7) as client:
            async def probe(name,url):
                try:
                    # Registry reachability does not require downloading their
                    # potentially huge complete package-version documents.
                    res=await (client.get(url,headers=headers.get(name,{})) if name=='judge_backend' else client.head(url,headers=headers.get(name,{})))
                    checks[name]=res.is_success
                    if name=='judge_backend' and os.getenv('LLM_PROVIDER','ollama')=='ollama' and res.is_success:
                        model=os.getenv('OLLAMA_MODEL','phi3:mini')
                        available={item.get('name','') for item in res.json().get('models',[])}
                        checks['judge_model']=model in available or model+':latest' in available
                except Exception: checks[name]=False
            async def bounded_probe(name,url):
                try:await asyncio.wait_for(probe(name,url),timeout=1.0)
                except TimeoutError:checks[name]=False
            await asyncio.gather(*(bounded_probe(k,v) for k,v in targets.items()))
        _last=(time.monotonic(),checks)
    if service=='docker_security':
        from app.image_jobs import connect, _task
        try:
            connection=connect()
            try:checks['image_job_journal']=connection.execute('SELECT count(*) FROM jobs').fetchone()[0]<64
            finally:connection.close()
            checks['image_job_worker']=_task is not None and not _task.done()
        except Exception:checks['image_job_journal']=False
        if os.getenv('GUARDIAN_EXTERNAL_SCANNERS','false').lower() == 'true':
            checks['hadolint']=bool(shutil.which('hadolint'))
            checks['trivy']=bool(shutil.which('trivy'))
        else:
            checks.pop('hadolint',None)
            checks.pop('trivy',None)
            from app.engines.native import NativeDockerLint
            checks['guardian_native_lint']=NativeDockerLint().analyze('FROM scratch\n').completed
    ok=all(checks.values())
    return JSONResponse(status_code=200 if ok else 503,content={
        'service':service,'agent':service,'agent_name':service,'status':'ok' if ok else 'degraded','checks':checks})
