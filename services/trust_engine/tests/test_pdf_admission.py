import threading
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from app import main, interfaces, runtime


@pytest.mark.asyncio
async def test_pdf_rendering_is_off_event_loop(monkeypatch):
    async def scan(*args):return SimpleNamespace(model_dump=lambda **kwargs: {})
    def render(*args):
        assert threading.current_thread() is not threading.main_thread()
        return b'%PDF-test'
    monkeypatch.setattr(main,'get_scan',scan)
    monkeypatch.setattr(interfaces,'_render_audit_pdf',render)
    response=await interfaces.audit_pdf('request',object())
    assert response.body == b'%PDF-test'


@pytest.mark.asyncio
async def test_pdf_export_fails_explicitly_at_capacity(monkeypatch):
    async def scan(*args):return SimpleNamespace(model_dump=lambda **kwargs: {})
    async def saturated(*args):raise TimeoutError('full')
    monkeypatch.setattr(main,'get_scan',scan)
    monkeypatch.setattr(runtime,'bounded_work',saturated)
    with pytest.raises(HTTPException) as error:
        await interfaces.audit_pdf('request',object())
    assert error.value.status_code == 503
