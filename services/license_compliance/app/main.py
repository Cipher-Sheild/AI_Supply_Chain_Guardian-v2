"""
License Compliance microservice -- identifies the license of every
AI-suggested dependency in an artifact's manifest and flags any that
conflict with the project's configured license policy.

Pipeline (see README for full write-up):
  Stage 0 (extraction.py)      -- parse the manifest into a clean list
                                   of (name, version, ecosystem) deps.
  Stage 1 (license_lookup.py)  -- identify each dependency's license:
                                   registry metadata fast path, ScanCode
                                   Python-API fallback for anything the
                                   fast path can't normalize. Redis-
                                   cached (cache.py) since a package's
                                   license doesn't change between scans.
  Stage 2 (policy.py)          -- load the project's configurable
                                   license policy from config.yml.
  Stage 3 (conflict_engine.py) -- compare each identified license
                                   against policy, produce a verdict +
                                   confidence + plain-language reason
                                   per dependency, then fuse into the
                                   final AgentResult.

Concurrency
-----------
All direct dependencies' Stage 1 lookups run CONCURRENTLY
(asyncio.gather) against a single shared, connection-pooled
httpx.AsyncClient created at startup -- not one client per request and
not a sequential loop -- since for a dependency tree of any real size,
the wall-clock cost of this service is almost entirely "waiting on N
network round-trips to a registry", and those round-trips are
independent of each other. The basic transitive check (see
_transitive_candidates) is a second, smaller gather() over the capped
set of declared sub-dependency names collected during Stage 1.

This service is stateless -- it never talks to Postgres. Redis IS used,
but purely as a performance cache; every code path is written to keep
working (degraded, not broken) if Redis is unreachable, since a cache
must never become a hard dependency for a correctness-critical service.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
import yaml
from fastapi import FastAPI

from app.cache import LicenseCache
from app.conflict_engine import evaluate_all, fuse
from app.extraction import Dependency, SkippedEntry, extract_dependencies
from app.license_lookup import LicenseResult, identify_license
from app.policy import Policy, load_policy
from app.schemas import AgentResult, ArtifactRequest

logger = logging.getLogger("license_compliance.main")

AGENT_NAME = "license_compliance"

_CONFIG_PATH = Path(__file__).parent.parent / "config.yml"


def _load_config() -> dict:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


_config = _load_config()
_policy: Policy = load_policy(_config)

_http_client: Optional[httpx.AsyncClient] = None
_cache: Optional[LicenseCache] = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    global _http_client, _cache
    # A shared, connection-pooled client so concurrent registry lookups
    # reuse connections instead of each paying a fresh TLS handshake --
    # meaningful at the scale of "every dependency in a real project".
    _http_client = httpx.AsyncClient(timeout=2.0, limits=httpx.Limits(max_connections=16, max_keepalive_connections=8))
    _cache = LicenseCache(ttl_seconds=_policy.cache_ttl_days * 24 * 60 * 60)
    await _cache.connect()
    yield
    if _http_client is not None:
        await _http_client.aclose()
    if _cache is not None:
        await _cache.close()


app = FastAPI(title=f"AI Supply Chain Guardian -- {AGENT_NAME}", lifespan=_lifespan)


@app.get("/health")
async def health():
    from app.readiness import readiness
    return await readiness(AGENT_NAME)



_registry_slots = asyncio.Semaphore(16)

async def _lookup_with_cache_inner(client: httpx.AsyncClient, cache: LicenseCache, dep: Dependency) -> LicenseResult:
    key = LicenseCache.key_for(dep.ecosystem, dep.name, dep.version)
    cached = await cache.get(key)
    if cached is not None:
        cached["from_cache"] = True
        return LicenseResult(**{k: v for k, v in cached.items() if k != "from_cache"})

    result = await identify_license(client, dep.name, dep.version, dep.ecosystem)
    # Only cache a result we're not going to immediately need to
    # reinterpret (e.g. don't bother caching total network failures --
    # let the next scan retry the registry rather than pinning a
    # transient outage into the cache for days).
    if result.source != "unknown" or result.spdx_expressions:
        await cache.set(key, result.__dict__)
    return result


async def _lookup_with_cache(client, cache, dep):
    async with _registry_slots:
        try: return await asyncio.wait_for(_lookup_with_cache_inner(client,cache,dep),timeout=3.0)
        except TimeoutError:
            return LicenseResult(spdx_expressions=[], confidence=0.0, source="unknown", warnings=["license lookup deadline exceeded"])


async def _basic_transitive_candidates(
    dependencies: list[Dependency], license_results: dict[str, LicenseResult], policy: Policy
) -> list[Dependency]:
    """
    Best-effort, single-level transitive check (see README "Known
    limitations" for why full graph resolution is out of scope): each
    direct dependency's own declared sub-dependency *names* (collected
    for free during Stage 1's registry call, no extra network round
    trip) are turned into unpinned Dependency candidates, capped so a
    large project doesn't explode the number of registry calls.
    """
    if not policy.transitive_enabled:
        return []

    seen_direct_names = {d.name.lower() for d in dependencies}
    candidates: list[Dependency] = []
    for dep in dependencies:
        key = f"{dep.ecosystem}:{dep.name}:{dep.version or 'unresolved'}"
        result = license_results.get(key)
        if result is None:
            continue
        for sub_name in result.declared_transitive_names:
            if sub_name.lower() in seen_direct_names:
                continue
            if len(candidates) >= policy.transitive_max_candidates:
                break
            candidates.append(
                Dependency(name=sub_name, version=None, ecosystem=dep.ecosystem, direct=False, via=dep.name,filename=dep.filename,line_number=dep.line_number)
            )
            seen_direct_names.add(sub_name.lower())
    return candidates


# Filenames we're willing to treat as a dependency manifest when the
# caller doesn't explicitly declare `type: "dependency"`.
from app.capabilities import MATRIX, supports
_RECOGNIZED_MANIFEST_FILENAMES = set(MATRIX["dependency_filenames"] + MATRIX["unsupported_manifests"])


def _looks_like_dependency_artifact(artifact: ArtifactRequest) -> bool:
    """
    Guard against non-dependency artifacts (Phase A audit fix).

    Without this, a plain code file's `import`/`def`/`os.system` tokens
    can get matched by extraction.py's requirements.txt-style content
    heuristic (`_guess_ecosystem`'s content-sniff fallback) and
    misinterpreted as package names -- a real bug found in Ahmed's
    audit. We only attempt extraction when the artifact is explicitly
    declared as a dependency manifest, or -- absent an explicit type --
    is clearly named like one.
    """
    kind = artifact.type or artifact.artifact_type
    if kind is not None:
        return supports(AGENT_NAME, kind)
    if not artifact.filename:
        return False
    name = artifact.filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in _RECOGNIZED_MANIFEST_FILENAMES or (name.startswith("requirements") and name.endswith(".txt"))


@app.post("/analyze", response_model=AgentResult)
async def analyze(artifact: ArtifactRequest) -> AgentResult:
    start = time.perf_counter()

    filename=artifact.filename or artifact.file_path or ''
    basename=filename.replace('\\','/').rsplit('/',1)[-1].lower()
    if (artifact.type or artifact.artifact_type)=='license' or basename in MATRIX.get('license_filenames',[]):
        from app.native_license import identify_text
        expressions,operator,confidence,warnings=identify_text(artifact.content)
        dependency=Dependency(name=basename or 'license',version=None,ecosystem='license_text',filename=filename,line_number=1)
        result=LicenseResult(spdx_expressions=expressions,confidence=confidence,source='native_spdx_text',warnings=warnings)
        fused=fuse(evaluate_all([dependency],{f'license_text:{dependency.name}:unresolved':result},_policy))
        fused['evidence']['scope']='Supplied license text only; does not establish the licensing of other project files.'
        fused['evidence']['warnings']=warnings
        if not expressions:
            fused.update(coverage='partial',unresolved=True,decision_floor='review')
        return AgentResult(agent_name=AGENT_NAME,**fused)

    if not _looks_like_dependency_artifact(artifact):
        return AgentResult(agent_name=AGENT_NAME, status="stub", findings=[], evidence=None)

    client = _http_client or httpx.AsyncClient(timeout=2.0, limits=httpx.Limits(max_connections=16, max_keepalive_connections=8))
    cache = _cache or LicenseCache()
    if _cache is None:
        await cache.connect()

    try:
        dependencies, skipped = extract_dependencies(artifact.model_dump())
    except (ValueError, TypeError) as exc:
        return AgentResult(agent_name=AGENT_NAME, status="error", coverage="none", evidence={"error": str(exc)})
    from app.dependency_graph import LOCK_NAMES,npm_graph
    filename=artifact.filename or artifact.file_path or ''
    from app.dependency_manifests import parse
    graph=npm_graph(artifact.content) if filename.replace('\\','/').rsplit('/',1)[-1].lower() in LOCK_NAMES else parse(filename,artifact.content)
    if filename.replace('\\','/').rsplit('/',1)[-1].lower()=='go.mod':
        from app.go_modules import resolve
        try:graph=await resolve(client,artifact.content)
        except ValueError as error:return AgentResult(agent_name=AGENT_NAME,status='error',coverage='none',evidence={'error':str(error)})
        dependencies=[Dependency(name=node['name'],version=node['version'],ecosystem='go',direct=node['direct'],filename=filename) for node in graph['nodes']]
        skipped=[SkippedEntry(raw=str(item.get('package','')),ecosystem='go',reason=item['reason']) for item in graph['unresolved']]
    if not dependencies:
        evidence = {"dependencies_scanned": 0, "note": "No recognized dependency manifest found."}
        if graph:evidence['dependency_graph']=graph
        if skipped:
            evidence["skipped"] = [{"raw": s.raw, "ecosystem": s.ecosystem, "reason": s.reason} for s in skipped]
        return AgentResult(
            agent_name=AGENT_NAME,
            status="warn" if skipped else "pass",
            coverage="partial" if skipped else "full",
            unresolved=bool(skipped),
            decision_floor="review" if skipped else "accept",
            findings=[],
            evidence=evidence,
        )

    # Stage 1, direct dependencies: fully concurrent.
    if len(dependencies)>100:
        skipped.append(SkippedEntry(raw='',ecosystem='node' if graph else 'unknown',reason=f'{len(dependencies)-100} dependencies exceed registry verification work budget'))
        dependencies=dependencies[:100]

    direct_results = await asyncio.gather(*[_lookup_with_cache(client, cache, dep) for dep in dependencies])
    license_results: dict[str, LicenseResult] = {
        f"{dep.ecosystem}:{dep.name}:{dep.version or 'unresolved'}": result
        for dep, result in zip(dependencies, direct_results)
    }

    # Basic transitive check -- second, bounded round.
    transitive_deps = [] if graph else await _basic_transitive_candidates(dependencies, license_results, _policy)
    if transitive_deps:
        transitive_results = await asyncio.gather(
            *[_lookup_with_cache(client, cache, dep) for dep in transitive_deps]
        )
        for dep, result in zip(transitive_deps, transitive_results):
            license_results[f"{dep.ecosystem}:{dep.name}:{dep.version or 'unresolved'}"] = result

    all_dependencies = dependencies + transitive_deps
    verdicts = evaluate_all(all_dependencies, license_results, _policy)
    fused = fuse(verdicts)
    fused["evidence"]["elapsed_seconds"] = round(time.perf_counter() - start, 4)
    fused["evidence"]["transitive_candidates_checked"] = len(transitive_deps)
    fused['evidence']['dependency_graph']=graph
    # Manifest entries we deliberately couldn't turn into a scannable
    # dependency (a `-r` include, a git/workspace-protocol npm dep, an
    # unrecognized requirements.txt line, etc.) — surfaced explicitly so
    # nothing silently vanishes from the report without a trace.
    if skipped:
        fused["coverage"] = "partial"
        fused["unresolved"] = True
        if fused.get("decision_floor") != "reject": fused["decision_floor"] = "review"
    fused["evidence"]["skipped"] = [{"raw": s.raw, "ecosystem": s.ecosystem, "reason": s.reason} for s in skipped]

    return AgentResult(agent_name=AGENT_NAME, **fused)

from app.runtime import BoundsMiddleware
app.add_middleware(BoundsMiddleware)
