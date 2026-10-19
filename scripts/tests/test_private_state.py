import os
from pathlib import Path
import pytest
from runtime.private_state import private_state_file


def test_state_defaults_are_private_and_per_user(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    path = Path(private_state_file('scans.sqlite3'))
    assert path.parent.stat().st_mode & 0o777 == 0o700
    path.write_text('private')
    assert private_state_file(path.name) == str(path)
    assert path.stat().st_mode & 0o777 == 0o600


def test_state_defaults_refuse_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    root = tmp_path / '.local/state/guardian'
    root.mkdir(parents=True)
    target = tmp_path / 'unrelated'
    target.write_text('keep')
    (root / 'scans.sqlite3').symlink_to(target)
    with pytest.raises(ValueError, match='symlink'):
        private_state_file('scans.sqlite3')
    assert target.read_text() == 'keep'
