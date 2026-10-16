import httpx
from typing import Dict, Any
from app.registry.pypi_client import fetch_pypi_metadata
from app.registry.npm_client import fetch_npm_metadata

async def run_existence_check(ecosystem: str, pkg_name: str, client: httpx.AsyncClient, version: str='') -> Dict[str, Any]:
    if ecosystem == "python":
        meta = await fetch_pypi_metadata(pkg_name, client)
    elif ecosystem=='javascript':
        meta = await fetch_npm_metadata(pkg_name, client)
    else:
        from app.registry_metadata import metadata
        meta=await metadata(client,ecosystem,pkg_name,version)
        
    return meta
