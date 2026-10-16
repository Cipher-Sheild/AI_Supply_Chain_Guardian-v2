"""
Redis caching layer for Stage 1 (license identification) results.

A dependency's license doesn't change between scans -- `requests==2.31.0`
has the same license today as it did yesterday. Caching the (comparatively
expensive) registry-API-plus-possible-ScanCode-fallback lookup keyed by
`license:{ecosystem}:{name}:{version}` means repeated scans of the same
or overlapping dependency trees (the common case in practice) skip that
work entirely on a cache hit. This is the concrete answer to the "agents
should be very effective and optimised" requirement -- see README for
measured cache-hit vs cache-miss latency.

Connection details come from `REDIS_URL`, the same environment variable
already used elsewhere in this project (see `.env.example` /
`docker-compose.yml`), not a newly invented one.

This service must keep working even if Redis is briefly unreachable --
it's a performance optimization, not a correctness dependency. Every
method here fails open: a Redis error is logged once and treated as a
cache miss / no-op, never raised up to the request handler.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger("license_compliance.cache")

_DEFAULT_TTL_SECONDS = 3 * 24 * 60 * 60  # 3 days — overridable via config.yml


class LicenseCache:
    """Thin async wrapper around a Redis client, scoped to license lookups."""

    def __init__(self, redis_url: Optional[str] = None, ttl_seconds: int = _DEFAULT_TTL_SECONDS):
        self._redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._ttl_seconds = ttl_seconds
        self._client: Optional[aioredis.Redis] = None
        self._warned_unavailable = False
        from app.ttl_cache import TTLCache
        self._memory = TTLCache(ttl=ttl_seconds)

    async def connect(self) -> None:
        try:
            self._client = aioredis.from_url(self._redis_url, decode_responses=True, socket_connect_timeout=0.2, socket_timeout=0.2, max_connections=16)
            await self._client.ping()
            logger.info("License cache connected")
        except Exception as exc:  # noqa: BLE001 — cache must never block startup
            logger.warning("License cache: could not connect to Redis (%s) — running without cache.", exc)
            self._client = None

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def key_for(ecosystem: str, name: str, version: Optional[str]) -> str:
        # Unpinned dependencies (version=None) are cached under "unresolved"
        # with a short effective TTL applied by the caller if desired --
        # kept distinct from a real pinned version so a later scan with a
        # real version doesn't collide with a stale unpinned-guess entry.
        version_part = version if version else "unresolved"
        return f"license:{ecosystem}:{name.lower()}:{version_part}"

    async def get(self, key: str) -> Optional[dict]:
        if self._client is None:
            return self._memory.get(key)
        try:
            raw = await self._client.get(key)
        except Exception as exc:  # noqa: BLE001
            if not self._warned_unavailable:
                logger.warning("License cache read failed (%s) — continuing without cache.", exc)
                self._warned_unavailable = True
            return self._memory.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    async def set(self, key: str, value: dict, ttl_seconds: Optional[int] = None) -> None:
        self._memory.set(key, value, ttl_seconds)
        if self._client is None:
            return
        try:
            await self._client.set(key, json.dumps(value), ex=ttl_seconds or self._ttl_seconds)
        except Exception as exc:  # noqa: BLE001
            if not self._warned_unavailable:
                logger.warning("License cache write failed (%s) — continuing without cache.", exc)
                self._warned_unavailable = True
