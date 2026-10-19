import pytest
from app import main, local_judge


@pytest.mark.asyncio
async def test_local_models_warm_sequentially(monkeypatch):
    calls=[];pending=[]
    monkeypatch.setenv('LLM_PROVIDER','local')
    monkeypatch.setattr(main,'preload_embeddings',lambda: calls.append('embeddings'))
    monkeypatch.setattr(local_judge,'warm',lambda: calls.append('judge'))
    monkeypatch.setattr(main,'_spawn',pending.append)
    await main._startup()
    try:
        await pending[0]
        assert calls == ['embeddings','judge']
    finally:
        for coroutine in pending[1:]:coroutine.close()
