"""Bounded data adapters for public Rust and Go registries; no package execution."""
import json
import re
from datetime import datetime,timezone
from urllib.parse import quote
import httpx


async def metadata(client,ecosystem,name,version=''):
    result={'status':500,'age_days':-1,'maintainer_count':0,'downloads_last_month':-1,
            'license':None,'published_versions':[],'profile':'existence_metadata'}
    if ecosystem=='rust':
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',name):return result
        url='https://crates.io/api/v1/crates/'+quote(name,safe='')
    elif ecosystem=='go':
        if not re.fullmatch(r'[A-Za-z0-9._~/-]{1,512}',name) or any(part in {'','..','.'} for part in name.split('/')):return result
        if not re.fullmatch(r'v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?',version):
            return {**result,'reason':'Go proxy lookup requires an exact module version'}
        escaped=''.join('!'+char.lower() if char.isupper() else char for char in name)
        escaped_version=''.join('!'+char.lower() if char.isupper() else char for char in version)
        url='https://proxy.golang.org/'+escaped+'/@v/'+quote(escaped_version,safe='!')+'.info'
    else:return {**result,'reason':'unsupported registry ecosystem'}
    try:
        async with client.stream('GET',url,timeout=2,headers={'User-Agent':'Guardian/1.0 (artifact security review)'}) as response:
            result['status']=response.status_code
            if response.status_code==404:return result
            if response.status_code!=200:return {**result,'status':500}
            raw=bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                if len(raw)>2*1024*1024:raise ValueError('registry response exceeds data budget')
            data=json.loads(raw)
        result['data_source']=url
        if ecosystem=='rust':
            crate=data['crate'];result['published_versions']=[entry['num'] for entry in data.get('versions',[])]
            created=crate.get('created_at')
            if created:result['age_days']=(datetime.now(timezone.utc)-datetime.fromisoformat(created.replace('Z','+00:00'))).days
            selected=next((entry for entry in data.get('versions',[]) if entry['num']==version.lstrip('=v')),None)
            if selected:result['license']=selected.get('license')
        else:
            if data.get('Version')!=version:raise ValueError('Go proxy version identity mismatch')
            result['published_versions']=[version]
    except (httpx.HTTPError,ValueError,KeyError,TypeError):return {**result,'status':500}
    return result
