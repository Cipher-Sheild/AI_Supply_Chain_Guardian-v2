"""Feature logging must not follow a planted link or broaden permissions."""
import importlib.util
from pathlib import Path
import sys


def test_feature_log_refuses_symlink(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / 'services/trust_engine'))
    # Isolate the service import from other utility tests' app packages.
    spec = importlib.util.spec_from_file_location('audit_features', root / 'services/trust_engine/app/features.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / 'unrelated'
    target.write_text('unchanged')
    link = tmp_path / 'observations.jsonl'
    link.symlink_to(target)
    monkeypatch.setenv('FEATURE_LOG_PATH', str(link))
    monkeypatch.setattr(module, 'feature_event', lambda *args: {'safe': True})
    module.append_feature_event({})
    assert target.read_text() == 'unchanged'
