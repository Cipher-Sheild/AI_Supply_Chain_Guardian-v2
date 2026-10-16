"""Keep repeated regression runs out of the application's durable journal."""
import pytest

@pytest.fixture(autouse=True)
def isolated_callback_journal(tmp_path,monkeypatch):
    monkeypatch.setenv('CALLBACK_OUTBOX_PATH',str(tmp_path/'callbacks.sqlite3'))
    monkeypatch.setattr('app.outbox._box',None)


@pytest.fixture(autouse=True)
def isolate_judge_cache():
    from app.judge import _judge_cache
    _judge_cache.clear()
    yield
    _judge_cache.clear()


@pytest.fixture(autouse=True)
def legacy_unit_scoring_without_trained_classifier(monkeypatch):
    # Dedicated classifier tests explicitly enable it; old rule tests own their vectors.
    monkeypatch.setenv('PROMPT_CLASSIFIER_ENABLED','false')
