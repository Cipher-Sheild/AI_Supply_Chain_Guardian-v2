import time
from typing import Any, Optional, Dict, Tuple

class ResultCache:
    """
    In-memory + Redis cache for CVE scanning and image checks.
    """

    def __init__(self, ttl_seconds: int = 86400):
        self.ttl_seconds = ttl_seconds
        from app.ttl_cache import TTLCache
        self._memory_cache = TTLCache(ttl=ttl_seconds)
        self._redis_client = None
        self._init_redis()

    def _init_redis(self):
        try:
            import redis
            import os
            host = os.getenv("REDIS_HOST", "localhost")
            port = int(os.getenv("REDIS_PORT", 6379))
            client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), socket_connect_timeout=0.2, socket_timeout=0.2, max_connections=8)
            self._redis_client = client
        except Exception:
            self._redis_client = None

    def get(self, key: str) -> Optional[Any]:
        # 1. Try Redis
        if self._redis_client:
            try:
                import json
                val = self._redis_client.get(key)
                if val:
                    return json.loads(val)
            except Exception:
                pass

        # 2. In-memory fallback
        return self._memory_cache.get(key)

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        ttl_val = ttl if ttl is not None else self.ttl_seconds

        # 1. Try Redis
        if self._redis_client:
            try:
                import json
                self._redis_client.setex(key, ttl_val, json.dumps(value))
            except Exception:
                pass

        # 2. In-memory fallback
        self._memory_cache.set(key, value, ttl_val)

# Global cache instance
cache_instance = ResultCache()
