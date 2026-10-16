"""Native TOML/Go dependency inventories and Cargo lock graph extraction.

No package manager executes. Exact submitted lock nodes and unresolved sources
are distinguished from declared version constraints and local project roots.
"""
import re
import tomllib
from packaging.requirements import Requirement

FILENAMES={'pyproject.toml','pipfile','cargo.toml','cargo.lock','go.mod','go.sum','poetry.lock','uv.lock'}


def parse(filename,content):
    try:return _parse(filename,content)
    except (KeyError,AttributeError,TypeError,IndexError) as exc:
        raise ValueError('malformed dependency manifest structure') from exc


def _parse(filename,content):
    name=filename.replace('\\','/').rsplit('/',1)[-1].lower()
    if name not in FILENAMES:return None
    nodes=[];edges=[];unresolved=[]
    def node(ecosystem,package,version,direct=True,registry=True,**details):
        if not isinstance(package,str) or not isinstance(version,str):raise ValueError('dependency name/version must be strings')
        if len(nodes)>=10000:raise ValueError('dependency inventory exceeds work budget')
        value={'id':f'{ecosystem}:{package}@{version}','ecosystem':ecosystem,'name':package,'version':version,
               'direct':direct,'registry':registry,**details}
        nodes.append(value);return value
    def python_entry(raw):
        requirement=Requirement(raw)
        if requirement.url:
            unresolved.append({'package':requirement.name,'reason':'direct URL requires source verification'});return
        node('python',requirement.name,str(requirement.specifier),marker=str(requirement.marker or ''))
    if name in {'go.mod','go.sum'}:
        seen=set();in_require=False
        for number,line in enumerate(content.splitlines(),1):
            raw=line.strip();line=raw.split('//',1)[0].strip()
            if not line:continue
            if name=='go.sum':
                parts=line.split()
                if len(parts)!=3 or not parts[2].startswith('h1:'):raise ValueError('malformed go.sum entry')
                package,version,checksum=parts;version=version.removesuffix('/go.mod')
                if (package,version) not in seen:
                    node('go',package,version,False,checksum=checksum);seen.add((package,version))
                continue
            if line=='require (':in_require=True;continue
            if line==')':in_require=False;continue
            if line.startswith(('replace ','exclude ','retract ')):
                unresolved.append({'line':number,'reason':'replacement/exclusion/retraction requires complete module resolution'});continue
            if line.startswith('require '):line=line[len('require '):]
            elif not in_require:continue
            parts=line.split()
            if len(parts)!=2:raise ValueError('malformed go.mod require entry')
            node('go',parts[0],parts[1],direct='// indirect' not in raw)
        unresolved.append({'reason':'module inventory is not a resolved MVS dependency graph'})
    else:
        data=tomllib.loads(content)
        if name=='pyproject.toml':
            project=data.get('project',{})
            for raw in project.get('dependencies',[]):python_entry(raw)
            for values in project.get('optional-dependencies',{}).values():
                for raw in values:python_entry(raw)
            for raw in data.get('build-system',{}).get('requires',[]):python_entry(raw)
            if 'dependencies' in project.get('dynamic',[]):unresolved.append({'reason':'dynamic project dependencies require build metadata; builds are not executed'})
            poetry=data.get('tool',{}).get('poetry',{})
            sections=[poetry.get('dependencies',{}),poetry.get('dev-dependencies',{})]
            sections.extend(group.get('dependencies',{}) for group in poetry.get('group',{}).values())
            for section in sections:
                for package,value in section.items():
                    if package.lower()=='python':continue
                    if isinstance(value,dict):
                        if any(key in value for key in ('git','path','url','source')):
                            unresolved.append({'package':package,'reason':'Poetry non-registry source unresolved'});continue
                        value=value.get('version','')
                    if not isinstance(value,str):raise ValueError('invalid Poetry dependency')
                    # Poetry caret/tilde constraints are retained, not treated as exact pins.
                    node('python',package,value)
        elif name=='pipfile':
            for section in ('packages','dev-packages'):
                for package,value in data.get(section,{}).items():
                    if isinstance(value,dict):
                        if any(key in value for key in ('git','path','file','index','editable')):
                            unresolved.append({'package':package,'reason':'Pipfile source requires independent verification'});continue
                        value=value.get('version','')
                    node('python',package,value)
        elif name=='cargo.toml':
            sections=[data.get(key,{}) for key in ('dependencies','dev-dependencies','build-dependencies')]
            for target in data.get('target',{}).values():sections.extend(target.get(key,{}) for key in ('dependencies','dev-dependencies','build-dependencies'))
            for section in sections:
                for package,value in section.items():
                    if isinstance(value,dict):
                        if any(key in value for key in ('git','path','registry','workspace')):
                            unresolved.append({'package':package,'reason':'Cargo alternative source/workspace requires companion verification'});continue
                        package=value.get('package',package);value=value.get('version','')
                    node('rust',package,value)
        elif name in {'cargo.lock','poetry.lock','uv.lock'}:
            entries=data.get('package',[])
            if not isinstance(entries,list):raise ValueError('lock package entries must be a list')
            ecosystem='rust' if name=='cargo.lock' else 'python'
            by_name={}
            for entry in entries:
                source=entry.get('source')
                registry=(isinstance(source,str) and source in {'registry+https://github.com/rust-lang/crates.io-index','registry+sparse+https://index.crates.io/'}) if ecosystem=='rust' else (not source or isinstance(source,dict) and source.get('registry') in {'https://pypi.org/simple','https://pypi.org/simple/'})
                item=node(ecosystem,entry['name'],entry['version'],False,registry,checksum=entry.get('checksum'))
                by_name.setdefault(item['name'],[]).append(item)
                if source and not registry:unresolved.append({'package':item['name'],'reason':'lock entry uses an unverified source'})
            for entry,parent in zip(entries,nodes):
                dependencies=entry.get('dependencies',[])
                if isinstance(dependencies,dict):dependencies=[{'name':key,'constraint':value} for key,value in dependencies.items()]
                for dependency in dependencies:
                    if isinstance(dependency,str):
                        parts=dependency.split();package=parts[0];version=parts[1] if len(parts)>1 else None
                    elif isinstance(dependency,dict):package=dependency['name'];version=dependency.get('version')
                    else:raise ValueError('unsupported lock dependency edge')
                    matches=[item for item in by_name.get(package,[]) if version is None or item['version']==version]
                    target=matches[0]['id'] if len(matches)==1 else None
                    edges.append({'from':parent['id'],'to':target,'name':package})
                    if target is None:unresolved.append({'package':package,'reason':'lock graph edge unresolved or ambiguous'})
            incoming={edge['to'] for edge in edges if edge['to']}
            roots={item['id'] for item in nodes if not item['registry'] and item['id'] not in incoming}
            for item in nodes:
                item['direct']=any(edge['from'] in roots and edge['to']==item['id'] for edge in edges)
                if not item['registry'] and item['id'] in incoming:
                    unresolved.append({'package':item['name'],'reason':'local dependency source requires companion review'})
    return {'format':name,'nodes':nodes,'edges':edges,'unresolved':unresolved,'complete':not unresolved,
            'resolution':'locked' if name.endswith('.lock') or name=='cargo.lock' else 'declared',
            'node_count':len(nodes),'edge_count':len(edges)}
