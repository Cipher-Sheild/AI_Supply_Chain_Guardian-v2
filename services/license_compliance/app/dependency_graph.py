"""Read the resolved npm installation graph without invoking npm or installing code.

The graph is evidence from the submitted lockfile, not proof the registry archive
matches it. Unsupported links, sources, and unresolved edges remain explicit.
"""
import json
import re
from urllib.parse import urlsplit

LOCK_NAMES = {'package-lock.json','npm-shrinkwrap.json'}
NAME = re.compile(r'^(?:@[a-zA-Z0-9._~-]+/)?[a-zA-Z0-9._~-]+$')


def npm_graph(content):
    data=json.loads(content)
    if not isinstance(data,dict) or data.get('lockfileVersion') not in (2,3):
        raise ValueError('npm graph requires lockfileVersion 2 or 3')
    packages=data.get('packages')
    if not isinstance(packages,dict) or '' not in packages:
        raise ValueError('lockfile requires a root packages entry')
    if len(packages)>10000:
        raise ValueError('lockfile exceeds 10000 package graph nodes')
    nodes=[];edges=[];unresolved=[]
    for path,item in packages.items():
        if not isinstance(item,dict): raise ValueError('package entry must be an object')
        if not path: continue
        if not isinstance(path,str) or path.startswith('/') or '..' in path.split('/') or '\\' in path:
            raise ValueError('invalid package installation path')
        name=item.get('name') or path.rsplit('node_modules/',1)[-1]
        version=item.get('version')
        if not isinstance(name,str) or not NAME.fullmatch(name):
            unresolved.append({'path':path,'reason':'unsupported package name or workspace path'});continue
        if item.get('link'):
            unresolved.append({'path':path,'reason':'workspace/link target requires companion source'});continue
        if not isinstance(version,str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?',version):
            unresolved.append({'path':path,'reason':'missing exact registry version'});continue
        resolved=item.get('resolved','')
        if resolved and (not isinstance(resolved,str) or urlsplit(resolved).scheme!='https' or urlsplit(resolved).hostname!='registry.npmjs.org'):
            unresolved.append({'path':path,'reason':'non-public-registry source requires source verification'})
        nodes.append({'id':path,'name':name,'version':version,'ecosystem':'javascript',
                      'integrity':item.get('integrity'),'direct':False})
    ids={node['id'] for node in nodes}
    def resolve(parent,name):
        current=parent
        while True:
            candidate=(current+'/' if current else '')+'node_modules/'+name
            if candidate in ids: return candidate
            if not current: return None
            current=current.rsplit('/',1)[0] if '/' in current else ''
    for path,item in packages.items():
        if path and path not in ids: continue
        peer_meta=item.get('peerDependenciesMeta',{})
        if not isinstance(peer_meta,dict) or any(not isinstance(value,dict) for value in peer_meta.values()):
            raise ValueError('peer dependency metadata must contain objects')
        for section in ('dependencies','devDependencies','optionalDependencies','peerDependencies'):
            values=item.get(section,{})
            if not isinstance(values,dict): raise ValueError('dependency section must be an object')
            for name,spec in values.items():
                if not isinstance(name,str) or not NAME.fullmatch(name) or not isinstance(spec,str):
                    raise ValueError('invalid dependency edge')
                target=resolve(path,name)
                optional=section=='optionalDependencies' or bool(peer_meta.get(name,{}).get('optional'))
                edges.append({'from':path or 'root','to':target,'name':name,'constraint':spec,'kind':section,'optional':optional})
                if target is None and not optional:
                    unresolved.append({'path':path,'package':name,'reason':'required graph edge unresolved'})
                if len(edges)>50000: raise ValueError('lockfile exceeds 50000 graph edges')
    direct={edge['to'] for edge in edges if edge['from']=='root' and edge['to']}
    for node in nodes:node['direct']=node['id'] in direct
    return {'format':'npm-lock-v2-v3','nodes':nodes,'edges':edges,'unresolved':unresolved,
            'complete':not unresolved,'node_count':len(nodes),'edge_count':len(edges)}
