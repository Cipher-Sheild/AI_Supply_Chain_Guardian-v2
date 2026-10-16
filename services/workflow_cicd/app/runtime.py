"""Operational bounds; no scoring or feature contract logic."""
import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor

MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "2097152"))
WORKERS = max(1, int(os.getenv("SCAN_WORKERS", "4")))
_pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="scanner")
_slots = asyncio.Semaphore(WORKERS)

async def bounded_work(fn, *args):
    # Queue admission is bounded too. Cancelling a request does not release a
    # slot until the underlying thread really ends.
    await asyncio.wait_for(_slots.acquire(), timeout=0.1)
    loop = asyncio.get_running_loop()
    try:
        future = loop.run_in_executor(_pool, fn, *args)
    except BaseException:
        _slots.release()
        raise
    future.add_done_callback(lambda _: _slots.release())
    return await asyncio.shield(future)

class BoundsMiddleware:
    def __init__(self, app):
        self.app = app
        self.active = 0
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        if self.active >= WORKERS:
            return await self.reject(send, 503, b'{"detail":"scanner capacity exhausted"}')
        self.active += 1
        deadline = time.monotonic() + 9.8
        try:
            body = bytearray()
            while True:
                try:
                    message = await asyncio.wait_for(receive(), timeout=max(0.001, deadline-time.monotonic()))
                except TimeoutError:
                    return await self.reject(send, 408, b'{"detail":"body receive deadline exceeded"}')
                if message["type"] == "http.disconnect": return
                body.extend(message.get("body", b""))
                if len(body) > MAX_BODY_BYTES:
                    return await self.reject(send, 413, b'{"detail":"request body too large"}')
                if not message.get("more_body", False): break
            delivered = False
            async def replay():
                nonlocal delivered
                if delivered: return await receive()
                delivered = True
                return {"type":"http.request", "body":bytes(body), "more_body":False}
            response_started = False
            async def tracked_send(message):
                nonlocal response_started
                if message["type"] == "http.response.start": response_started = True
                await send(message)
            try:
                await asyncio.wait_for(self.app(scope, replay, tracked_send), timeout=max(0.001, deadline-time.monotonic()))
            except TimeoutError:
                if not response_started:
                    await self.reject(send, 504, b'{"detail":"request deadline exceeded"}')
        finally:
            self.active -= 1
    async def reject(self, send, status, body):
        await send({"type":"http.response.start", "status":status, "headers":[(b"content-type",b"application/json")]})
        await send({"type":"http.response.body", "body":body})
