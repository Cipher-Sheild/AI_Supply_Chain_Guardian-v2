import json
import redis.asyncio as redis
import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Fallback in-memory cache for local testing without redis
from app.ttl_cache import TTLCache
_IN_MEMORY_CACHE = TTLCache()

class Cache:
    def __init__(self, ttl_seconds: int = 14400): # 4 hours TTL
        self.ttl = ttl_seconds
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=0.2, socket_timeout=0.2, max_connections=16)
        self.use_memory_fallback = False

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        if self.use_memory_fallback:
            return _IN_MEMORY_CACHE.get(key)
        try:
            val = await self.redis.get(key)
            if val:
                return json.loads(val)
            return None
        except (redis.RedisError, OSError):
            logger.warning("Redis connection failed, falling back to in-memory cache.")
            self.use_memory_fallback = True
            return _IN_MEMORY_CACHE.get(key)

    async def set(self, key: str, value: Dict[str, Any]) -> None:
        if self.use_memory_fallback:
            _IN_MEMORY_CACHE.set(key, value, self.ttl)
            return
        try:
            await self.redis.setex(key, self.ttl, json.dumps(value))
        except (redis.RedisError, OSError):
            self.use_memory_fallback = True
            _IN_MEMORY_CACHE.set(key, value, self.ttl)

cache = Cache()
