from .python_extractor import extract_dependencies as extract_python_deps
from .npm_extractor import extract_dependencies as extract_npm_deps

def extract_all_dependencies(file_path: str, content: str = None):
    if file_path.endswith("requirements.txt") or file_path.endswith("requirements_python.txt"):
        return extract_python_deps(file_path, content)
    elif file_path.endswith("package.json"):
        return extract_npm_deps(file_path, content)
    else:
        # Default fallback by guessing
        if "package.json" in file_path:
            return extract_npm_deps(file_path, content)
        return extract_python_deps(file_path, content)


def extract_report(file_path, content):
    import json
    from app.dependency_manifests import parse
    extended=parse(file_path,content)
    if extended is not None:
        return [(node['ecosystem'],node['name'],node['version'],f'{file_path}:0') for node in extended['nodes'] if node.get('registry',True)],extended['unresolved']
    from app.dependency_graph import LOCK_NAMES, npm_graph
    if file_path.replace('\\','/').rsplit('/',1)[-1].lower() in LOCK_NAMES:
        graph=npm_graph(content)
        return [('javascript',node['name'],node['version'],f'{file_path}:0') for node in graph['nodes']],graph['unresolved']
    from packaging.requirements import Requirement, InvalidRequirement
    if file_path.lower().endswith("package.json") or content.lstrip().startswith("{"):
        try: data = json.loads(content)
        except (ValueError, TypeError) as exc: raise ValueError("Malformed package.json") from exc
        if not isinstance(data, dict): raise ValueError("package.json must be an object")
        deps=[]; skipped=[]
        for section in ("dependencies","devDependencies","peerDependencies","optionalDependencies"):
            values=data.get(section, {})
            if not isinstance(values,dict): raise ValueError(f"{section} must be an object")
            for name, version in values.items():
                if not isinstance(version,str): raise ValueError("dependency version must be a string")
                if version.startswith(("file:","git+","http:","https:","github:","workspace:","link:","npm:")):
                    skipped.append({"package":name,"reason":"non-registry dependency unresolved"}); continue
                line_number = next((i for i,line in enumerate(content.splitlines(),1) if json.dumps(name) in line),0)
                deps.append(("javascript",name,version,f"{file_path}:{line_number}"))
        return deps,skipped
    deps=[]; skipped=[]
    for line_number,raw in enumerate(content.splitlines(),1):
        line=raw.split(" #",1)[0].strip()
        if not line or line.startswith("#"): continue
        if line.startswith(("-r","-e","--requirement","--editable","git+","http:","https:","file:")):
            skipped.append({"line":line_number,"reason":"included/local/VCS dependency unresolved"}); continue
        if line.startswith(("--","-i")): continue
        try: requirement=Requirement(line)
        except InvalidRequirement as exc: raise ValueError(f"Malformed requirement on line {line_number}") from exc
        if requirement.url:
            skipped.append({"line":line_number,"reason":"URL dependency unresolved"}); continue
        deps.append(("python",requirement.name,str(requirement.specifier),f"{file_path}:{line_number}"))
    return deps,skipped
