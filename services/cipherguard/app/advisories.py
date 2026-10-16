"""Guardian data adapter for OSV advisories; no OSV scanner program is used."""
import asyncio
import json
import re
import time
import httpx
from app.ttl_cache import TTLCache

ECOSYSTEMS={'python':'PyPI','javascript':'npm','rust':'crates.io','go':'Go'}
_cache=TTLCache(max_entries=1024,ttl=3600)
_slots=asyncio.Semaphore(16)


def exact_version(value,ecosystem):
    value=value.strip()
    if ecosystem=='python':
        from packaging.specifiers import SpecifierSet,InvalidSpecifier
        from packaging.version import Version,InvalidVersion
        try:
            parts=list(SpecifierSet(value)) if value.startswith(('=','<','>','!','~')) else []
            if parts:
                if len(parts)!=1 or parts[0].operator!='==' or '*' in parts[0].version:return None
                value=parts[0].version
            Version(value);return value
        except (InvalidSpecifier,InvalidVersion):return None
    value=value.removeprefix('==').removeprefix('=')
    return value if re.fullmatch(r'v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?',value) else None


def severity(record):
    database=record.get('database_specific') or {}
    if not isinstance(database,dict):raise ValueError('malformed advisory database metadata')
    declared=str(database.get('severity','')).lower()
    if declared=='moderate':return 'medium'
    if declared in {'critical','high','medium','low'}:return declared
    scores=[]
    from cvss import CVSS3,CVSS4,CVSS2
    vectors=record.get('severity',[])
    if not isinstance(vectors,list) or any(not isinstance(item,dict) for item in vectors):raise ValueError('malformed severity vectors')
    for item in vectors:
        vector=item.get('score','')
        if not isinstance(vector,str) or len(vector)>1024:continue
        try:
            parser=CVSS4 if vector.startswith('CVSS:4.') else CVSS3 if vector.startswith('CVSS:3.') else CVSS2
            scores.append(float(parser(vector).scores()[0]))
        except Exception:continue
    if scores:
        score=max(scores)
        return 'critical' if score>=9 else 'high' if score>=7 else 'medium' if score>=4 else 'low'
    return 'high'  # Confirmed but unrated vulnerability: conservative review policy.


async def lookup(client,ecosystem,name,version):
    osv_ecosystem=ECOSYSTEMS.get(ecosystem,ecosystem if ecosystem.startswith(('Alpine:','Debian:','Ubuntu:')) else None)
    if not osv_ecosystem:return {'completed':False,'error':'unsupported advisory ecosystem','vulns':[]}
    key=json.dumps([osv_ecosystem,name,version])
    cached=_cache.get(key)
    if cached is not None:return {**cached,'from_cache':True}
    output={'completed':False,'vulns':[],'source':'https://api.osv.dev/v1/query','queried_at':time.time()}
    token=None;seen_tokens=set();ids=set()
    try:
        async with _slots:
            for _ in range(8):
                payload={'package':{'name':name,'ecosystem':osv_ecosystem},'version':version}
                if token:payload['page_token']=token
                async with client.stream('POST',output['source'],json=payload,timeout=2) as response:
                    if response.status_code!=200:raise ValueError('advisory feed did not return 200')
                    raw=bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw)>2*1024*1024:raise ValueError('advisory response exceeds data budget')
                    data=json.loads(raw)
                if not isinstance(data,dict) or set(data)-{'vulns','next_page_token'} or not isinstance(data.get('vulns',[]),list):raise ValueError('malformed advisory response')
                for record in data.get('vulns',[]):
                    if not isinstance(record,dict) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',str(record.get('id',''))):raise ValueError('malformed advisory identity')
                    if record.get('withdrawn') or record['id'] in ids:continue
                    ids.add(record['id'])
                    output['vulns'].append({'id':record['id'],'aliases':record.get('aliases',[]),
                        'severity':severity(record),'summary':str(record.get('summary') or 'Known vulnerability')[:1000],
                        'modified':record.get('modified'),'severity_provided':bool(record.get('severity') or (record.get('database_specific') or {}).get('severity'))})
                    if len(output['vulns'])>256:raise ValueError('advisory count exceeds work budget')
                token=data.get('next_page_token')
                if not token:
                    output['completed']=True;_cache.set(key,output);return output
                if not isinstance(token,str) or token in seen_tokens:raise ValueError('invalid advisory pagination token')
                seen_tokens.add(token)
            raise ValueError('advisory pagination budget exhausted')
    except (httpx.HTTPError,ValueError,TypeError):
        output['error']='Advisory lookup unavailable or incomplete; review required.'
        return output
