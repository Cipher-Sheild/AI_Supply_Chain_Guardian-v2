"""Owned Go module graph reader with MVS and Go 1.17 graph pruning.

Reads public proxy go.mod data only; never executes Go or imports artifact paths.
Root replace/exclude directives are conservatively unresolved in this adapter.
"""
import asyncio
import re
import shlex
import time
from urllib.parse import quote
import httpx

VERSION=re.compile(r'^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$')
PATH=re.compile(r'^[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*$')

def version_key(value):
    match=VERSION.fullmatch(value)
    if not match:raise ValueError('Invalid Go semantic version')
    major,minor,patch,pre=match.groups()
    if any(len(part)>1 and part.startswith('0') for part in (major,minor,patch)):
        raise ValueError('Invalid Go semantic version: leading zero')
    identifiers=tuple((0,int(part)) if part.isdigit() else (1,part) for part in (pre or '').split('.'))
    return int(major),int(minor),int(patch),1 if pre is None else 0,identifiers

def parse_mod(content):
    requirements=[];unsupported=[];go=(1,16);module=None;block=None
    for number,raw in enumerate(content.splitlines(),1):
        # Go module paths cannot contain a colon/URL scheme; comments are not URLs.
        line=raw.split('//',1)[0].strip()
        if not line:continue
        if line==')':
            if block is None:raise ValueError('Unexpected module block end')
            block=None;continue
        parts=shlex.split(line)
        if not parts:continue
        directive=block or parts.pop(0)
        if not block and parts==['(']:block=directive;continue
        if directive=='module':
            if len(parts)!=1:raise ValueError('Invalid module directive')
            module=parts[0]
        elif directive=='go':
            if len(parts)!=1 or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?',parts[0]):raise ValueError('Invalid Go directive')
            go=tuple(int(value) for value in parts[0].split('.')[:2])
        elif directive=='require':
            if len(parts)!=2 or not PATH.fullmatch(parts[0]) or any(part in {'.','..'} for part in parts[0].split('/')):raise ValueError('Invalid module requirement')
            version_key(parts[1]);requirements.append((parts[0],parts[1],'// indirect' not in raw))
        elif directive in {'replace','exclude'}:
            unsupported.append({'line':number,'directive':directive,'reason':'Root replacements/exclusions require source-aware resolution'})
        elif directive not in {'retract','toolchain','godebug'}:
            unsupported.append({'line':number,'directive':directive,'reason':'Unrecognized module directive'})
    if block:raise ValueError('Unterminated module block')
    return {'module':module,'go':go,'requirements':requirements,'unsupported':unsupported}

def escape(value):return ''.join('!'+char.lower() if char.isupper() else char for char in value)

async def resolve(client,content,max_modules=150,deadline_seconds=6):
    root=parse_mod(content);unresolved=list(root['unsupported']);selected={};edges=[];visited=set();fetched=0
    if not root['module']:raise ValueError('Go module directive missing')
    # A root replacement may change any dependency edge. Do not fetch/analyze
    # the original module and misrepresent it as the replacement's contents.
    if unresolved:
        return {'format':'go.mod','nodes':[],'edges':[],'unresolved':unresolved,'complete':False,
                'resolution':'unresolved_root_directives','node_count':0,'edge_count':0}
    root_names={name for name,_,_ in root['requirements']}
    direct_names={name for name,_,direct in root['requirements'] if direct}
    deadline=time.monotonic()+deadline_seconds;slots=asyncio.Semaphore(16)
    async def load(name,version,unpruned):
        nonlocal fetched
        key=(name,version,unpruned)
        if key in visited:return None
        visited.add(key)
        if fetched>=max_modules or time.monotonic()>=deadline:
            unresolved.append({'package':name,'version':version,'reason':'Module graph resource budget exceeded'});return None
        fetched+=1
        url='https://proxy.golang.org/'+escape(name)+'/@v/'+quote(escape(version),safe='!')+'.mod'
        try:
            async with slots:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError()
                async with asyncio.timeout(remaining):
                    async with client.stream('GET',url,timeout=min(2,remaining),follow_redirects=False) as response:
                        if response.status_code!=200:raise ValueError('Proxy HTTP '+str(response.status_code))
                        raw=bytearray()
                        async for chunk in response.aiter_bytes():
                            raw.extend(chunk)
                            if len(raw)>262144:raise ValueError('Module metadata exceeds size budget')
                    child=parse_mod(raw.decode('utf-8'))
                    if child['module']!=name:raise ValueError('Proxy module identity mismatch')
                    # Dependency replace/exclude directives are ignored by Go.
                    unknown=[item for item in child['unsupported'] if item['directive'] not in {'replace','exclude'}]
                    unresolved.extend({'package':name,**item} for item in unknown)
                    return name,version,unpruned,child
        except (httpx.HTTPError,ValueError,UnicodeError,TimeoutError) as error:
            unresolved.append({'package':name,'version':version,'reason':str(error) or 'Module graph deadline exceeded'});return None
    def select(name,version):
        if name not in selected or version_key(version)>version_key(selected[name]):selected[name]=version
    queue=[]
    for name,version,_ in root['requirements']:
        select(name,version);edges.append({'from':'root','name':name,'required_version':version});queue.append((name,version,root['go']<(1,17)))
    while queue:
        batch=queue;queue=[]
        outcomes=await asyncio.gather(*(load(*entry) for entry in batch))
        for outcome in outcomes:
            if outcome is None:continue
            name,version,inherited,child=outcome
            unpruned=inherited or child['go']<(1,17)
            for dependency,required,_ in child['requirements']:
                select(dependency,required)
                edges.append({'from':f'go:{name}@{version}','name':dependency,'required_version':required})
                # Root requirements always contribute their immediate edges.
                # Modern transitive dependencies' edges are pruned unless they
                # are reachable through a legacy unpruned dependency.
                if unpruned or dependency in root_names:
                    queue.append((dependency,required,unpruned))
    nodes=[{'id':f'go:{name}@{version}','ecosystem':'go','name':name,'version':version,
            'direct':name in direct_names,'registry':True} for name,version in sorted(selected.items())]
    for edge in edges:edge['to']=f"go:{edge['name']}@{selected[edge['name']]}"
    return {'format':'go.mod','nodes':nodes,'edges':edges,'unresolved':unresolved,'complete':not unresolved,
            'resolution':'go_mvs_module_graph','pruning':root['go']>=(1,17),'scope':'Module requirements; not package imports or a reproducible build proof',
            'metadata_fetched':fetched,'node_count':len(nodes),'edge_count':len(edges)}
