"""
Stage 0 — dependency extraction.

Parses an incoming artifact's manifest into a clean, ecosystem-tagged
list of dependencies: `(name, version, ecosystem)`. Downstream stages
(license_lookup, policy, conflict_engine) never need to know anything
about manifest *syntax* — they work off `Dependency` objects.

Design notes
------------
- `extract_dependencies(artifact) -> list[Dependency]` is the single
  public entrypoint, mirroring the dispatch pattern used by
  `services/prompt_injection/app/extraction.py` (`extract_spans`).
- Per-ecosystem parsers are registered in `_EXTRACTORS` so new
  ecosystems can be plugged in later without touching dispatch logic
  (see project doc §7 — only Python/`requirements.txt` and
  Node/`package.json` are in scope for this version).
- Parsing is best-effort, not a full spec-compliant parser for either
  format. See README "Known limitations" for what's deliberately not
  handled (e.g. full PEP 508 environment marker evaluation, npm
  workspace/monorepo `file:`/`workspace:` protocol dependencies).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str]  # None if unpinned (e.g. "requests" with no specifier)
    ecosystem: str  # "python" | "node"
    raw: str = ""  # original manifest line/entry, kept for evidence/debugging
    direct: bool = True  # False for basic transitive candidates (see main.py)
    filename: Optional[str] = None
    line_number: int = 0
    via: Optional[str] = None  # parent package name, set when direct=False


# ---------------------------------------------------------------------------
# Python: requirements.txt
# ---------------------------------------------------------------------------

# Matches `package`, `package[extra1,extra2]`, `package==1.2.3`,
# `package>=1.0,<2.0`, stopping before an environment marker (`; ...`).
_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)"  # package name
    r"(?:\[[^\]]*\])?"  # optional extras, ignored
    r"\s*(.*?)\s*"  # version specifier (raw, may be empty)
    r"(?:;.*)?$"  # optional environment marker, ignored
)

# The first pinned/bounding version we can extract, e.g. from
# "==1.2.3", ">=1.0,<2.0", "~=1.4". We take the first `==` exact pin if
# present (most informative for a license lookup); otherwise the first
# version number mentioned, on a best-effort basis. Anything looser
# than that is treated as unpinned (version=None) — a real license
# lookup against a moving target isn't reliable, so we say so via
# `needs_review` further downstream rather than guessing.
_EXACT_PIN_RE = re.compile(r"==\s*([A-Za-z0-9.\-+_!]+)")
_ANY_VERSION_RE = re.compile(r"[A-Za-z0-9.\-+_!]+")


@dataclass(frozen=True)
class SkippedEntry:
    """A manifest line/entry we deliberately did not turn into a Dependency, and why."""

    raw: str
    ecosystem: str
    reason: str


def _extract_python_requirements(content: str, filename: Optional[str]) -> tuple[list[Dependency], list[SkippedEntry]]:
    deps: list[Dependency] = []
    skipped: list[SkippedEntry] = []
    for line_number, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            skipped.append(SkippedEntry(raw=line, ecosystem="python", reason="'-r' include file is not resolved in this pass"))
            continue
        if line.startswith(("-e ", "--editable ")):
            skipped.append(SkippedEntry(raw=line, ecosystem="python", reason="editable/VCS install is not resolved in this pass"))
            continue
        if line.startswith("-"):
            # Other pip flags (--index-url, --hash, etc.) — not a dependency, not worth reporting as skipped.
            continue

        from packaging.requirements import Requirement, InvalidRequirement
        line = line.split(" #", 1)[0].strip()
        try: requirement = Requirement(line)
        except InvalidRequirement as exc: raise ValueError("Malformed requirement") from exc
        if requirement.url:
            skipped.append(SkippedEntry(raw=line, ecosystem="python", reason="URL dependency unresolved"))
            continue
        name = requirement.name
        exact = [spec.version for spec in requirement.specifier if spec.operator == "==" and "*" not in spec.version]
        version = exact[0] if len(exact) == 1 else None

        deps.append(Dependency(name=name, version=version, ecosystem="python", raw=line, filename=filename, line_number=line_number))
    return deps, skipped


# ---------------------------------------------------------------------------
# Node: package.json
# ---------------------------------------------------------------------------

# npm version ranges commonly seen: "^1.2.3", "~1.2.3", "1.2.3",
# ">=1.0.0 <2.0.0", "*", "latest". We strip leading range operators to
# get a usable version for an exact registry lookup; ranges with a
# space (multiple comparators) or non-numeric specs (git/file/workspace
# protocols) are left unresolved (version=None).
_NPM_RANGE_PREFIX_RE = re.compile(r"^[\^~>=<]*\s*")
_NPM_PROTOCOL_RE = re.compile(r"^(git|file|link|workspace|github|npm):", re.IGNORECASE)


def _clean_npm_version(raw_version: str) -> tuple[Optional[str], Optional[str]]:
    """Returns (cleaned_version, skip_reason). skip_reason is None if it resolved fine."""
    raw_version = raw_version.strip()
    if not raw_version or raw_version in ("*", "latest"):
        return None, None  # unpinned, but still scanned — same treatment as Python's loose ranges
    if _NPM_PROTOCOL_RE.match(raw_version):
        return None, f"'{raw_version}' uses a non-registry protocol (git/file/workspace/etc.), not resolvable via npm registry"
    if " " in raw_version or "||" in raw_version:
        # Compound range — ambiguous which exact version would be
        # installed without running a real resolver. Still scanned
        # unpinned (not skipped) — same policy as Python loose ranges.
        return None, None
    cleaned = _NPM_RANGE_PREFIX_RE.sub("", raw_version)
    return cleaned or None, None


def _extract_node_package_json(content: str, filename: Optional[str]) -> tuple[list[Dependency], list[SkippedEntry]]:
    try:
        manifest = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("Malformed package.json") from exc
    if not isinstance(manifest, dict):
        raise ValueError("package.json must be an object")

    deps: list[Dependency] = []
    skipped: list[SkippedEntry] = []
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = manifest.get(field)
        if section is not None and not isinstance(section, dict):
            raise ValueError(f"{field} must be an object")
        if section is None:
            continue
        for name, raw_version in section.items():
            if not isinstance(raw_version, str):
                raise ValueError("dependency version must be a string")
            version, skip_reason = _clean_npm_version(raw_version)
            if skip_reason:
                skipped.append(SkippedEntry(raw=f"{name}: {raw_version}", ecosystem="node", reason=skip_reason))
                continue
            deps.append(
                Dependency(name=name, version=version, ecosystem="node", raw=f"{name}: {raw_version}",filename=filename, line_number=next((i for i,line in enumerate(content.splitlines(),1) if json.dumps(name) in line),0))
            )
    return deps, skipped


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_EXTRACTORS: dict[str, Callable[[str, Optional[str]], tuple[list[Dependency], list[SkippedEntry]]]] = {
    "python": _extract_python_requirements,
    "node": _extract_node_package_json,
}


def _guess_ecosystem(artifact: dict) -> Optional[str]:
    """
    Figure out which manifest format we're looking at. Prefers an
    explicit `language`/`type`/`ecosystem` field, falls back to the
    filename, then a content sniff.
    """
    explicit = (
        artifact.get("ecosystem") or artifact.get("language") or artifact.get("type") or ""
    ).strip().lower()
    aliases = {
        "python": "python",
        "py": "python",
        "pip": "python",
        "requirements": "python",
        "requirements.txt": "python",
        "node": "node",
        "npm": "node",
        "javascript": "node",
        "js": "node",
        "package.json": "node",
    }
    if explicit in aliases:
        return aliases[explicit]

    filename = (artifact.get("filename") or "").lower()
    if filename.endswith("requirements.txt") or filename.endswith(".txt") and "requirement" in filename:
        return "python"
    if filename.endswith("package.json"):
        return "node"

    content = artifact.get("content", "") or ""
    stripped = content.lstrip()
    if stripped.startswith("{"):
        return "node"
    # requirements.txt lines look like `name==1.0` / `name>=1.0` / bare `name`
    if re.search(r"^[A-Za-z0-9][A-Za-z0-9._-]*\s*(==|>=|<=|~=|!=)?\s*[\w.]*\s*$", stripped.splitlines()[0] if stripped else ""):
        return "python"

    return None


def extract_dependencies(artifact: dict) -> tuple[list[Dependency], list[SkippedEntry]]:
    """Single public entrypoint. Returns ([], []) for an unrecognized/empty manifest."""
    from app.dependency_graph import LOCK_NAMES,npm_graph
    filename=artifact.get('filename') or artifact.get('file_path') or ''
    from app.dependency_manifests import parse
    extended=parse(filename,artifact.get('content',''))
    if extended is not None:
        from packaging.requirements import Requirement
        def version(item):
            raw=item['version']
            if item['ecosystem']=='python':
                if extended['resolution']=='locked':return raw
                try:
                    requirement=Requirement(item['name']+raw)
                    exact=next((part.version for part in requirement.specifier if part.operator=='==' and '*' not in part.version),None)
                    return exact
                except ValueError:return None
            return raw.lstrip('=') if raw.startswith('=') else raw
        return ([Dependency(name=item['name'],version=version(item),ecosystem='node' if item['ecosystem']=='javascript' else item['ecosystem'],direct=item['direct'],filename=filename)
                 for item in extended['nodes'] if item.get('registry',True)],
                [SkippedEntry(raw=str(item.get('package','')),ecosystem='unknown',reason=item['reason']) for item in extended['unresolved']])
    if filename.replace('\\','/').rsplit('/',1)[-1].lower() in LOCK_NAMES:
        graph=npm_graph(artifact.get('content',''))
        return ([Dependency(name=node['name'],version=node['version'],ecosystem='node',direct=node['direct'],filename=filename,
                            raw=node['id']) for node in graph['nodes']],
                [SkippedEntry(raw=str(item.get('path','')),ecosystem='node',reason=item['reason']) for item in graph['unresolved']])
    from app.capabilities import unsupported_path
    if unsupported_path(artifact.get("filename") or artifact.get("file_path")):
        return [], [SkippedEntry(raw="", ecosystem="unknown", reason="unsupported manifest format")]
    ecosystem = _guess_ecosystem(artifact)
    if ecosystem is None or ecosystem not in _EXTRACTORS:
        return [], []
    content = artifact.get("content", "") or ""
    filename = artifact.get("filename")
    return _EXTRACTORS[ecosystem](content, filename)
