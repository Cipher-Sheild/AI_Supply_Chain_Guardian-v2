"""Native OCI OS-package advisory analysis using Guardian inventory and OSV data."""
import asyncio
import httpx
from app.engines.oci_inventory import inventory
from app.advisories import lookup
from app.schema import Finding
from app.engines.result import EngineResult
from app.ttl_cache import TTLCache

_cache=TTLCache(max_entries=64,ttl=3600)


async def analyze_image(reference,path,line):
    cached=_cache.get(reference) if '@sha256:' in reference else None
    if cached is None:
        cached=await inventory(reference)
        if '@sha256:' in reference:_cache.set(reference,cached)
    packages=cached['packages'];findings=[]
    if len(packages)>1000:return EngineResult(False,'OS inventory exceeds advisory work budget'),cached
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=16)) as client:
        observations=await asyncio.gather(*(lookup(client,item['ecosystem'],item['name'],item['version']) for item in packages))
    for package,observation in zip(packages,observations):
        for vulnerability in observation['vulns']:
            severity=vulnerability['severity']
            findings.append(Finding(detector_id='guardian-cve:'+vulnerability['id'],file_path=path,line_number=line,
                preview=package['name']+' '+package['version'],confidence=1,severity=severity,
                reason=f"{vulnerability['id']} in verified image OS inventory: {vulnerability['summary']}",
                remediation='Update the pinned base image to a version confirmed unaffected by this advisory.',
                sources=['osv:'+vulnerability['id']],category='cve_vulnerability',hard_block=severity=='critical'))
    completed=all(item['completed'] for item in observations)
    return EngineResult(completed,None if completed else 'OS advisory lookup incomplete',findings=findings),cached
