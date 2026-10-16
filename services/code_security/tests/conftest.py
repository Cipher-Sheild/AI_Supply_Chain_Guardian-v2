"""Real scanner fixtures exercise warm request budgets after cold initialization."""
import pytest
@pytest.fixture(scope='session',autouse=True)
def warm_real_scanner():
    from app.main import run_semgrep
    # Production initializes this at startup; module-level TestClient has no lifespan.
    findings=run_semgrep('eval(input())\n','suite_warmup.py',90)
    assert findings, 'real Semgrep warm-up must execute bundled rules'
