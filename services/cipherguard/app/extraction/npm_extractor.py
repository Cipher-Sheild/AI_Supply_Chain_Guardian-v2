import json
from typing import List, Tuple

def extract_dependencies(file_path: str, content: str = None) -> List[Tuple[str, str, str, str]]:
    """
    Parses a package.json file and returns a list of dependencies.
    Returns: List of (ecosystem, package_name, version_spec, source_location)
    """
    if content is None:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            return []

    dependencies = []
    
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    # Check all common dependency sections in package.json
    sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies"
    ]

    for section in sections:
        if section in data and isinstance(data[section], dict):
            for pkg_name, version_spec in data[section].items():
                vs = str(version_spec).strip()
                # Skip non-registry dependencies (local files, git, http)
                if vs.startswith(("file:", "git+", "http://", "https://", "github:")):
                    continue
                dependencies.append(("javascript", pkg_name, vs, f"{file_path}:{section}"))
                
    return dependencies
