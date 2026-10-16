"""Guardian-owned analysis of submitted GitLab CI configuration.

Local extends/defaults are resolved without executing jobs. External includes
and downstream pipelines remain unresolved, never silently counted as scanned.
"""
import re
from copy import deepcopy
from app.schemas import AgentResult,Finding
from app.scanner import load_workflow,_CURL_PIPE_SHELL_RE

GLOBALS={'default','include','stages','variables','workflow','image','services','before_script','after_script','cache','spec'}


def analyze_gitlab(content,filename):
    parsed=load_workflow(content);findings=[];unresolved=[];jobs=[]
    defaults=parsed.get('default',{})
    if not isinstance(defaults,dict):raise ValueError('GitLab default must be a mapping')
    if 'include' in parsed:unresolved.append('Included configurations require companion artifacts; not fetched.')
    def merge(left,right):
        output=deepcopy(left)
        for key,value in right.items():
            output[key]=merge(output[key],value) if isinstance(output.get(key),dict) and isinstance(value,dict) else deepcopy(value)
        return output
    def resolve(name,trail=()):
        if name in trail or len(trail)>10:raise ValueError('cyclic or excessive GitLab extends')
        item=parsed.get(name)
        if not isinstance(item,dict):raise ValueError('GitLab job/template must be a mapping')
        output={}
        parents=item.get('extends',[])
        if isinstance(parents,str):parents=[parents]
        if not isinstance(parents,list) or any(not isinstance(parent,str) for parent in parents):raise ValueError('invalid GitLab extends')
        for parent in parents:
            if parent not in parsed:unresolved.append(f'Missing extends template for job {name}');continue
            output=merge(output,resolve(parent,trail+(name,)))
        return merge(output,item)
    def emit(job,code,severity,category,reason,remediation):
        line=next((i for i,text in enumerate(content.splitlines(),1) if text.startswith(str(job)+':')),1)
        findings.append(Finding(category=category,severity=severity,confidence=.9,
            location=f'{filename}:{line}',reason=reason,remediation=remediation,
            details={'rule_id':code,'job':job,'engine':'guardian_gitlab'}))
    for name,item in parsed.items():
        if name in GLOBALS or str(name).startswith('.'):continue
        if not isinstance(name,str) or not isinstance(item,dict):raise ValueError('GitLab job must be a named mapping')
        resolved=resolve(name)
        inherited=resolved.get('inherit',{})
        if isinstance(inherited,dict) and inherited.get('default') is False:job=resolved
        else:job=merge(defaults,resolved)
        jobs.append(name)
        if not any(key in job for key in ('script','trigger','run')):raise ValueError('GitLab job requires script, trigger, or run')
        if any(key in job for key in ('trigger','run')):unresolved.append(f'Job {name}: downstream pipeline/run steps not resolved')
        image=job.get('image',parsed.get('image'))
        if isinstance(image,dict):image=image.get('name')
        if image is not None:
            if not isinstance(image,str):raise ValueError('GitLab image must have a string name')
            if not re.search(r'@sha256:[a-fA-F0-9]{64}$',image):
                emit(name,'GLC001','medium','supply_chain','Job image is not pinned to an immutable digest.','Pin the verified image digest.')
        variables=merge(parsed.get('variables',{}) if isinstance(parsed.get('variables',{}),dict) else {},job.get('variables',{}) if isinstance(job.get('variables',{}),dict) else {})
        for key,value in variables.items():
            if isinstance(value,dict):value=value.get('value')
            if key in {'GIT_SSL_NO_VERIFY','CI_DEBUG_TRACE'} and str(value).lower() in {'true','1'}:
                emit(name,'GLC002','high' if key=='GIT_SSL_NO_VERIFY' else 'medium','insecure_transport' if key=='GIT_SSL_NO_VERIFY' else 'secret_exposure',f'{key} weakens transport or logging protections.','Disable this setting in production jobs.')
            if key=='DOCKER_TLS_CERTDIR' and value=='':
                emit(name,'GLC003','high','insecure_transport','Docker service TLS is disabled.','Enable authenticated TLS or avoid Docker-in-Docker.')
        services=job.get('services',parsed.get('services',[]))
        if not isinstance(services,list):raise ValueError('GitLab services must be a list')
        for service in services:
            service_name=service.get('name','') if isinstance(service,dict) else service
            if not isinstance(service_name,str):raise ValueError('invalid GitLab service name')
            if re.search(r'(?:^|/)docker:.*dind',service_name):
                emit(name,'GLC004','high','privileged_execution','Docker-in-Docker service requires verification of runner privilege and isolation.','Prefer a dedicated isolated builder and protected runner.')
        commands=[]
        for key in ('before_script','script','after_script'):
            value=job.get(key,parsed.get(key,[]) if key!='script' else [])
            if isinstance(value,str):commands.append(value)
            elif isinstance(value,list):
                pending=list(value);count=0
                while pending:
                    entry=pending.pop();count+=1
                    if count>1000:raise ValueError('excessive nested script entries')
                    if isinstance(entry,str):commands.append(entry)
                    elif isinstance(entry,list):pending.extend(entry)
                    else:raise ValueError('script entries must be strings')
            else:raise ValueError('script must be a string or list')
        for command in commands:
            if _CURL_PIPE_SHELL_RE.search(command):
                emit(name,'GLC005','high','remote_code_execution','Downloaded content is piped into an interpreter.','Verify downloaded content before executing it.')
            if re.search(r'\beval\b.*\$(?:\{|)(?:CI_MERGE_REQUEST|CI_COMMIT_MESSAGE)',command):
                emit(name,'GLC006','high','command_injection','Untrusted merge request or commit content reaches eval.','Treat repository metadata as data; avoid eval.')
        if job.get('allow_failure') is True and re.search(r'security|sast|audit|secret|scan',name,re.I):
            emit(name,'GLC007','high','security_gate_bypass','Security job failure is allowed without blocking the pipeline.','Make security failures block protected deployments.')
        if isinstance(job.get('artifacts'),dict):
            paths=job['artifacts'].get('paths',[])
            if not isinstance(paths,list):raise ValueError('artifact paths must be a list')
            for path in paths:
                if isinstance(path,str) and re.search(r'(?:^|/)(?:\.env(?:$|[.*])|id_rsa|.*\.(?:pem|key)$)',path):
                    emit(name,'GLC008','high','secret_exposure','Credential-shaped paths are included in uploaded artifacts.','Exclude private keys and environment credentials from artifacts.')
    if not jobs:raise ValueError('GitLab configuration has no executable jobs')
    return AgentResult(agent_name='workflow_cicd',status='fail' if any(f.severity=='high' for f in findings) else 'warn' if findings or unresolved else 'pass',
        coverage='partial' if unresolved else 'full',unresolved=bool(unresolved),decision_floor='review' if unresolved else 'accept',
        findings=findings,evidence={'engine':'guardian_gitlab','jobs_scanned':jobs,'unresolved':unresolved})
