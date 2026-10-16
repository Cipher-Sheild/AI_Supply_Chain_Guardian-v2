import asyncio
import httpx
import time
import re
from typing import List, Dict, Any, Tuple
from fastapi import FastAPI
from app.extraction import extract_all_dependencies, extract_report
from app.detection import run_existence_check, get_min_edit_distance, check_metadata_risk
from app.scoring import calculate_score
from app.schema import AgentResult, Finding
from app.registry.cache import cache
from app.advisories import lookup as lookup_advisories,exact_version

AGENT_NAME = "cipherguard"

app = FastAPI(title=f"AI Supply Chain Guardian — {AGENT_NAME}")


@app.get("/health")
async def health():
    from app.readiness import readiness
    return await readiness(AGENT_NAME)



@app.post("/analyze", response_model=AgentResult)
async def analyze(artifact: Dict[str, Any]) -> AgentResult:
    if any(artifact.get(key) is not None and not isinstance(artifact[key],str) for key in ('filename','file_path','type','artifact_type','format','ecosystem')):
        return AgentResult(agent_name=AGENT_NAME,status='error',coverage='none',unresolved=True,
                           evidence={'reason':'Artifact hints must be strings.'})
    from app.capabilities import supports, unsupported_path
    kind = artifact.get("type") or artifact.get("artifact_type")
    if kind and not supports(AGENT_NAME, kind):
        return AgentResult(agent_name=AGENT_NAME,status="stub",coverage="none")
    if unsupported_path(artifact.get("filename") or artifact.get("file_path")):
        return AgentResult(agent_name=AGENT_NAME,status="stub",coverage="partial",unresolved=True)
    file_path = artifact.get("filename") or artifact.get("file_path") or "unknown"
    content = artifact.get("content")

    # FAIL CLOSED: an artifact we cannot read is NOT a clean scan. Previously
    # a missing `content` fell through to scan_manifest -> the extractor, which
    # (a) tried to open() whatever `filename` the caller supplied -- an
    # arbitrary local file read via the HTTP endpoint -- and (b) returned
    # status="pass" with zero findings when that failed. Content must be sent
    # inline as a string. An empty string is a legitimately empty manifest and
    # still scans normally (-> pass); anything that is not a string is rejected.
    if not isinstance(content, str):
        return AgentResult(
            agent_name=AGENT_NAME,
            status="error",
            findings=[],
            evidence={
                "reason": "No readable manifest content in artifact payload -- expected a string 'content' field.",
                "severity": None,
                "confidence": 0.0,
                "total_findings": 0,
                "execution_time_ms": 0.0,
            },
        )

    if artifact.get("format") == "package.json" and file_path == "unknown": file_path = "package.json"
    return await scan_manifest(file_path, content)


async def process_dependency(
    ecosystem: str,
    pkg_name: str,
    version_spec: str,
    source_location: str,
    client: httpx.AsyncClient
) -> dict:
    # 1. Check Registry Existence & Fetch Metadata
    meta = await run_existence_check(ecosystem,pkg_name,client,version_spec) if ecosystem not in {'python','javascript'} else await run_existence_check(ecosystem,pkg_name,client)
    exact=exact_version(version_spec,ecosystem)
    if meta.get('status') == 200 and exact is not None:
        if 'published_versions' not in meta:
            return {'package':pkg_name,'ecosystem':ecosystem,'version':version_spec,'score':None,
                    'status':'error','error':'exact version existence not verified','finding':None}
        versions=meta['published_versions']
        if ecosystem=='python':
            from packaging.version import Version,InvalidVersion
            normalized=set()
            for published in versions:
                try:normalized.add(Version(published))
                except InvalidVersion:continue
            exists=Version(exact) in normalized
        else:exists=exact in versions or (ecosystem in {'javascript','rust'} and exact.removeprefix('v') in versions)
        if not exists:
            meta={**meta,'status':404,'missing_exact_version':exact}
    
    if meta.get("status", 500) not in {200,404}:
        return {"package": pkg_name, "ecosystem": ecosystem, "version": version_spec,
                "score": None, "status": "error", "error": "registry verification unavailable",
                "registry_http_status":meta.get('status'),"finding": None}
    # 2. Extract Heuristic Signals
    typosquat_dist, norm_dist = get_min_edit_distance(pkg_name, ecosystem)
    metadata_signals = check_metadata_risk(meta)
    
    # 3. Fusion Scoring
    score = calculate_score(meta, metadata_signals, typosquat_dist, norm_dist, pkg_name)
    
    # Format Recommendation based on Score Tier
    if score == 100:
        if meta.get("status") == 404:
            rec = ("Hard Block: Requested exact version does not exist on the registry." if meta.get("missing_exact_version")
                   else "Hard Block: Package does not exist on the registry (404). Extremely high hallucination risk.")
        else:
            rec = "Hard Block: Registry connection timeout or failure. Fail-closed."
    elif score >= 40:
        rec = "Middle-Band Flag: Package exists but exhibits suspicious heuristic signals. Manual review required."
    else:
        rec = "Clean Pass: Package exists and appears mature."
        
    all_signals = metadata_signals.copy()
    pkg_len = len(pkg_name)
    if typosquat_dist > 0 and ((pkg_len <= 3 and typosquat_dist == 1 and norm_dist <= 0.34) or (pkg_len >= 4 and ((1 <= typosquat_dist <= 2) or norm_dist <= 0.25))):
        all_signals.append(f"TYPOSQUAT_DIST_{typosquat_dist}")
        
    finding = Finding(
        detector_id="cipherguard",
        file_path=source_location.rsplit(":", 1)[0],
        line_number=int(source_location.rsplit(":", 1)[1]) if source_location.rsplit(":", 1)[1].isdigit() else 1,
        preview=f"{pkg_name} {version_spec}",
        confidence=1.0 if score == 100 else 0.8,
        severity="critical" if score >= 90 else ("medium" if score >= 40 else "low"),
        reason="Suspicious or non-existent dependency",
        remediation="Verify the package name. Do not install unless manually verified.",
        package=pkg_name,
        ecosystem=ecosystem,
        score=score,
        signals=all_signals,
        risk_contribution=score,
        recommendation=rec,
        hard_block=meta.get("status") == 404,
    )
    return {"package": pkg_name, "ecosystem": ecosystem, "version": version_spec, "score": score,
            "status": "fail" if score >= 90 else ("warn" if score >= 40 or meta.get('profile')=='existence_metadata' else "pass"),
            "coverage":"partial" if meta.get('profile')=='existence_metadata' else 'full',
            "data_source":meta.get('data_source'),
            "limitations":['Registry existence/metadata verified; ecosystem-specific similarity and maturity profile still requires independent calibration.'] if meta.get('profile')=='existence_metadata' else [],
            "finding": finding if score >= 40 else None}

async def scan_manifest(file_path: str, content: str = None) -> AgentResult:
    start_time = time.time()
    
    # 1. Extraction Phase
    try:
        deps, skipped = extract_report(file_path, content or "")
    except (ValueError, TypeError) as exc:
        return AgentResult(agent_name=AGENT_NAME, status="error", coverage="none", evidence={"error": str(exc)})
    findings = []
    graph=None
    from app.dependency_graph import LOCK_NAMES,npm_graph
    from app.dependency_manifests import parse
    graph=parse(file_path,content or '')
    if file_path.replace('\\','/').rsplit('/',1)[-1].lower() in LOCK_NAMES:
        graph=npm_graph(content or '')
    status = "pass"
    limits = httpx.Limits(max_connections=32, max_keepalive_connections=16)
    max_registry_checks=100
    async with httpx.AsyncClient(limits=limits, http2=True) as client:
        if file_path.replace('\\','/').rsplit('/',1)[-1].lower()=='go.mod':
            from app.go_modules import resolve
            try:graph=await resolve(client,content or '')
            except ValueError as error:return AgentResult(agent_name=AGENT_NAME,status='error',coverage='none',evidence={'error':str(error)})
            deps=[('go',node['name'],node['version'],f'{file_path}:0') for node in graph['nodes']]
            skipped=list(graph['unresolved'])
        if len(deps)>max_registry_checks:
            skipped.append({'reason':'registry verification budget exceeded','unchecked_nodes':len(deps)-max_registry_checks})
            deps=deps[:max_registry_checks]
        observations = await asyncio.gather(*[process_dependency(eco, pkg, ver, loc, client) for eco,pkg,ver,loc in deps])
    for observation in observations:
        if observation["finding"] is not None: findings.append(observation["finding"])
    if any(o["status"] == "fail" for o in observations): status = "fail"
    elif any(o["status"] == "error" for o in observations): status = "error"
    elif findings or skipped or any(o['status']=='warn' for o in observations): status = "warn"
    incomplete = bool(skipped) or any(o["status"] == "error" or o.get('coverage')=='partial' for o in observations)
    advisory_results=[]
    async with httpx.AsyncClient(limits=limits) as client:
        async def check_advisories(observation):
            version=exact_version(observation['version'],observation['ecosystem'])
            if observation['status'] in {'fail','error'}:return None
            if version is None:return {'package':observation['package'],'version':None,'completed':False,'vulns':[],
                                       'error':'Locked/exact version required for advisory assessment.'}
            return {'package':observation['package'],'version':version,
                    **await lookup_advisories(client,observation['ecosystem'],observation['package'],version)}
        advisory_results=[item for item in await asyncio.gather(*(check_advisories(observation) for observation in observations)) if item is not None]
    if any(not item['completed'] for item in advisory_results):incomplete=True
    for item in advisory_results:
        observation=next(o for o in observations if o['package']==item['package'] and exact_version(o['version'],o['ecosystem'])==item['version'])
        for vulnerability in item['vulns']:
            severity=vulnerability['severity'];risk={'critical':95,'high':65,'medium':40,'low':15}[severity]
            findings.append(Finding(detector_id='guardian-osv:'+vulnerability['id'],file_path=file_path,line_number=0,
                preview=item['package']+' '+str(item['version']),confidence=1,severity=severity,
                reason=f"{vulnerability['id']}: {vulnerability['summary']}",
                remediation='Upgrade to a version confirmed unaffected by this advisory and regenerate the lockfile.',
                package=item['package'],ecosystem=observation['ecosystem'],score=risk,signals=['OSV_CONFIRMED_ADVISORY'],
                risk_contribution=risk,recommendation='Reject' if severity=='critical' else 'Review',
                hard_block=severity=='critical',category='dependency_vulnerability'))
    if any(f.hard_block for f in findings):status='fail'
    elif findings or incomplete:status='warn' if status!='error' else status
    execution_time_ms = (time.time() - start_time) * 1000
    
    return AgentResult(
        agent_name="cipherguard",
        status=status,
        coverage="partial" if incomplete else "full",
        unresolved=incomplete,
        decision_floor="reject" if any(f.hard_block for f in findings) else ("review" if incomplete else "accept"),
        findings=findings,
        evidence={
            "dependency_graph":graph,
            "advisory_checks":advisory_results,
            "packages": [{k:v for k,v in o.items() if k != "finding"} for o in observations],
            "skipped": skipped,
            "severity": max((f.severity for f in findings),key=lambda value:{'low':1,'medium':2,'high':3,'critical':4}[value],default=None),
            "confidence": max((f.confidence for f in findings), default=0.0),
            "total_findings": len(findings),
            "execution_time_ms": round(execution_time_ms, 2),
        },
    )

from app.runtime import BoundsMiddleware
app.add_middleware(BoundsMiddleware)
