import httpx
import asyncio
import logging
from typing import Dict, Any, Tuple
from datetime import datetime, timezone
import dateutil.parser

from .cache import cache

logger = logging.getLogger(__name__)

# Configurable concurrency limits
SEMAPHORE = asyncio.Semaphore(16)

async def _fetch_with_retries(client: httpx.AsyncClient, url: str) -> Tuple[int, Dict[str, Any]]:
    from .http_json import fetch
    return await fetch(client,url,SEMAPHORE,logger)


async def fetch_pypi_metadata(pkg_name: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    # Check cache first
    cached = await cache.get(f"pypi:{pkg_name}")
    if cached:
        return cached

    url = f"https://pypi.org/pypi/{pkg_name}/json"
    
    status, data = await _fetch_with_retries(client, url)
        
    result = {
        "status": status,
        "age_days": -1,
        "maintainer_count": 0,
        "downloads_last_month": -1 # PyPI doesn't provide this in the standard JSON API
    }
    
    if status == 200 and data:
        result['published_versions']=list(data.get('releases',{}))
        # Age
        releases = data.get("releases", {})
        if releases:
            # Find the very first upload time
            earliest = None
            for ver, files in releases.items():
                for f in files:
                    dt_str = f.get("upload_time_iso_8601")
                    if dt_str:
                        dt = dateutil.parser.isoparse(dt_str)
                        if earliest is None or dt < earliest:
                            earliest = dt
            if earliest:
                now = datetime.now(timezone.utc)
                if earliest.tzinfo is None:
                    earliest = earliest.replace(tzinfo=timezone.utc)
                result["age_days"] = (now - earliest).days

        # Maintainer count
        info = data.get("info", {})
        authors = info.get("author_email") or ""
        maintainers = info.get("maintainer_email") or ""
        
        # Approximate unique emails by splitting commas
        all_emails = set()
        for e in authors.split(","):
            if e.strip(): all_emails.add(e.strip())
        for e in maintainers.split(","):
            if e.strip(): all_emails.add(e.strip())
            
        result["maintainer_count"] = len(all_emails) if all_emails else 1
        
    # Cache and return
    if status < 500:
        await cache.set(f"pypi:{pkg_name}", result)
    return result
