"""Shared scan-state serialization plus a legacy Redis adapter for tests.
Operational get_store() returns the SQL ScanStore. PostgreSQL/SQLite snapshots
persist every scan; Redis snapshots retain TTL only in the legacy adapter.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import redis.asyncio as redis_asyncio

from app.routing import RoutingDecision
from app.state import AgentCallRecord, GraphState, PendingCallback

logger = logging.getLogger(__name__)

# 1 hour. Stage 3 against a slow local model is ~10-70s per call and at
# most max_llm_calls_per_artifact (5) calls run concurrently, so a
# resolution normally lands within a couple of minutes; an hour leaves
# ample room for a caller to poll GET /scans/{id} after it resolves,
# while keeping artifact content from lingering in Redis.
DEFAULT_TTL_SECONDS = 3600
PENDING_STATE_TTL_SECONDS = int(os.getenv("PENDING_STATE_TTL_SECONDS", DEFAULT_TTL_SECONDS))

_SCAN_KEY = "asg:scan:{}"
_CALLBACK_KEY = "asg:callback:{}"


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class StoredScan:
    state: GraphState
    pending_since: dict[str, int] = field(default_factory=dict)


def serialize(stored: StoredScan) -> str:
    state = stored.state
    from app.redaction import redact
    # Callback fusion needs routing/results, not submitted source or options.
    # Keep only non-content file metadata in durable state.
    files=[{key:value for key,value in artifact.items() if key in {'filename','file_path','type','artifact_type','language','format','ecosystem'}} for artifact in state.get('files',[])]
    return json.dumps(redact({
        "request_id": state["request_id"],
        "files": files,
        "routing": [d.model_dump(mode="json") for d in state.get("routing", [])],
        "results": [r.model_dump(mode="json") for r in state.get("results", [])],
        "pending_callbacks": [p.model_dump(mode="json") for p in state.get("pending_callbacks", [])],
        "routing_notes": list(state.get("routing_notes", [])),
        "scoring": state.get("scoring",{}),
        "trust_result": state.get("trust_result", {}),
        "pending_since": stored.pending_since,
        **({"per_file_outcomes":state["per_file_outcomes"]} if "per_file_outcomes" in state else {}),
    }))


def deserialize(raw: str | bytes) -> StoredScan:
    data = json.loads(raw)
    state: GraphState = {
        "request_id": data["request_id"],
        "files": data.get("files", []),
        "routing": [RoutingDecision(**d) for d in data.get("routing", [])],
        "results": [AgentCallRecord(**r) for r in data.get("results", [])],
        "pending_callbacks": [PendingCallback(**p) for p in data.get("pending_callbacks", [])],
        "routing_notes": data.get("routing_notes", []),
        "scoring": data.get("scoring",{}),
        "trust_result": data.get("trust_result", {}),
    }
    if "per_file_outcomes" in data: state["per_file_outcomes"]=data["per_file_outcomes"]
    return StoredScan(state=state, pending_since=data.get("pending_since", {}))


class PendingStore:
    """Thin async wrapper over a redis.asyncio client. Every method may
    raise redis.exceptions.RedisError (or OSError); callers decide how to
    surface that."""

    def __init__(self, client, ttl_seconds: int = PENDING_STATE_TTL_SECONDS):
        self.client = client
        self.ttl = ttl_seconds

    async def save(self, stored: StoredScan) -> None:
        """Write the snapshot and a callback_id -> request_id mapping for
        every outstanding callback, atomically (MULTI/EXEC)."""
        request_id = stored.state["request_id"]
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.set(_SCAN_KEY.format(request_id), serialize(stored), ex=self.ttl)
            for p in stored.state.get("pending_callbacks", []):
                pipe.set(_CALLBACK_KEY.format(p.callback_id), request_id, ex=self.ttl)
            await pipe.execute()

    async def request_id_for_callback(self, callback_id: str) -> Optional[str]:
        value = await self.client.get(_CALLBACK_KEY.format(callback_id))
        if value is None:
            return None
        return value.decode() if isinstance(value, bytes) else value

    async def load(self, request_id: str) -> Optional[StoredScan]:
        raw = await self.client.get(_SCAN_KEY.format(request_id))
        return deserialize(raw) if raw is not None else None

    async def ttl_of(self, request_id: str) -> int:
        return await self.client.ttl(_SCAN_KEY.format(request_id))


    async def ping(self):
        return await self.client.ping()

    async def pending_ids(self):
        ids=[]
        async for key in self.client.scan_iter(match='asg:scan:*',count=100):
            key=key.decode() if isinstance(key,bytes) else key
            stored=await self.load(key.split(':',2)[2])
            if stored and stored.state.get('pending_callbacks'): ids.append(stored.state['request_id'])
        return ids

    @__import__('contextlib').asynccontextmanager
    async def locked(self, request_id):
        # Optimistic Redis transaction for legacy/test stores. Production uses
        # the database row lock in ScanStore, including normalized writes.
        async with self.client.pipeline(transaction=True) as pipe:
            key=_SCAN_KEY.format(request_id)
            await pipe.watch(key)
            raw=await pipe.get(key)
            stored=deserialize(raw) if raw else None
            yield stored
            if stored is not None:
                pipe.multi()
                pipe.set(key,serialize(stored),ex=self.ttl)
                await pipe.execute()


_client = None


def get_store():
    from app.scan_store import get_scan_store
    return get_scan_store()

async def close_store():
    from app.scan_store import get_scan_store
    await get_scan_store().close()
