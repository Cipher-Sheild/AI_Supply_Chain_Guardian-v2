import re
from typing import List, Tuple

def extract_dependencies(file_path: str, content: str = None) -> List[Tuple[str, str, str, str]]:
    """
    Parses a requirements.txt file and returns a list of dependencies.
    Returns: List of (ecosystem, package_name, version_spec, source_location)
    """
    if content is None:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            return []

    dependencies = []
    lines = content.splitlines()
    
    # Regex to capture the base package name, ignoring extras [], markers ;, and version specifiers
    # Valid Python package names contain only ASCII letters, digits, '.', '-', and '_'
    pkg_regex = re.compile(r"^([A-Za-z0-9\.\-\_]+)")

    for i, line in enumerate(lines):
        # Strip whitespace and ignore comments or empty lines
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r") or line.startswith("-i") or line.startswith("--"):
            continue

        # Skip direct URLs (git+, http, file, etc) that don't even have a package name declared
        if line.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://", "file://")):
            continue

        # Handle 'package @ URL' syntax by isolating the package name and checking if RHS is a registry-less URL
        if "@" in line:
            parts = line.split("@", 1)
            pkg_name = parts[0].strip()
            url_part = parts[1].strip()
            # If it's fetching from a URL, skip registry checks
            if url_part.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://", "file://")):
                continue
            line = pkg_name # For the regex below if it wasn't a URL

        # Extract base package name
        match = pkg_regex.match(line)
        if match:
            pkg_name = match.group(1)
            # The version spec is everything after the package name (minus extras/markers for simplicity, but we'll grab the raw tail)
            version_spec = line[len(pkg_name):].strip()
            # Clean up the package name (pip normalizes to lowercase and replaces _/. with -)
            # But we'll leave it as parsed for strict registry matching, PyPI is case-insensitive
            dependencies.append(("python", pkg_name, version_spec, f"{file_path}:{i+1}"))
            
    return dependencies
