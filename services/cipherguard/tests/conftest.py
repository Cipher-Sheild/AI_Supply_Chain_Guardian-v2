"""Contract/metadata unit suites are offline; advisory adapter tests own their feeds."""
import pytest

@pytest.fixture(autouse=True)
def offline_advisory_data(monkeypatch):
    async def clean(*args):return {'completed':True,'vulns':[],'source':'offline-unit-fixture'}
    monkeypatch.setattr('app.main.lookup_advisories',clean)
