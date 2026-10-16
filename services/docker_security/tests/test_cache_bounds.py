from app.ttl_cache import TTLCache

def test_ttl_size_and_failed_values(monkeypatch):
    monkeypatch.setattr('app.ttl_cache.time.monotonic', lambda: 100)
    cache = TTLCache(max_entries=2, ttl=5)
    for key in ('a','b','c'): cache.set(key, key)
    assert cache.get('a') is None
    cache.set('failed', {'status':503})
    assert cache.get('failed') is None
    cache.set('short', 'value', ttl=1)
    monkeypatch.setattr('app.ttl_cache.time.monotonic', lambda: 102)
    assert cache.get('short') is None
