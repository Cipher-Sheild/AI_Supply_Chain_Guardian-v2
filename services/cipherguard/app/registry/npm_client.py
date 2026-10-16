import httpx
import asyncio
import logging
import urllib.parse
from typing import Dict, Any, Tuple
from datetime import datetime, timezone
import dateutil.parser

from .cache import cache

logger = logging.getLogger(__name__)

SEMAPHORE = asyncio.Semaphore(16)

async def _fetch_with_retries(client: httpx.AsyncClient, url: str) -> Tuple[int, Dict[str, Any]]:
    from .http_json import fetch
    return await fetch(client,url,SEMAPHORE,logger)


async def fetch_npm_metadata(pkg_name: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    cached = await cache.get(f"npm:{pkg_name}")
    if cached:
        return cached

    # URL-encode the package name specifically keeping '@' safe if present, and encoding '/'
    # The user specifically tested: https://registry.npmjs.org/@babel%2Fcore works!
    # urllib.parse.quote will convert @ to %40 unless we specify safe="@"
    encoded_pkg = urllib.parse.quote(pkg_name, safe="@")
    
    url = f"https://registry.npmjs.org/{encoded_pkg}"
    
    status, data = await _fetch_with_retries(client, url)
        
    result = {
        "status": status,
        "age_days": -1,
        "maintainer_count": 0,
        "downloads_last_month": -1 # NPM registry API doesn't bundle downloads, requires a separate /downloads/ API call. Spec says 1 call.
    }
    
    if status == 200 and data:
        result['published_versions']=list(data.get('versions',{}))
        # Age
        time_data = data.get("time", {})
        created_str = time_data.get("created")
        if created_str:
            dt = dateutil.parser.isoparse(created_str)
            now = datetime.now(timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            result["age_days"] = (now - dt).days

        # Maintainers
        maintainers = data.get("maintainers", [])
        result["maintainer_count"] = len(maintainers) if maintainers else 1
        
    if status < 500:
        await cache.set(f"npm:{pkg_name}", result)
    return result
