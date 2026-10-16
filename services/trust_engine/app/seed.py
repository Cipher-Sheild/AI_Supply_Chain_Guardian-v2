import asyncio
from app.scan_store import get_scan_store
async def main():
    store=get_scan_store()
    await store.seed()
    await store.close()
if __name__ == '__main__': asyncio.run(main())
