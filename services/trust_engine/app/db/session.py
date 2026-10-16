"""Session dependency backed by the operational ScanStore engine."""
from app.scan_store import get_scan_store
async def get_session():
    store=get_scan_store()
    await store.initialize()
    async with store.sessions() as session:
        yield session
