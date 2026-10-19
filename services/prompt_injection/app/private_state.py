"""Private per-user defaults for standalone service state.

Explicit operator-configured deployment paths remain supported by each caller.
"""
import os
from pathlib import Path
import stat


def private_state_file(name):
    root = Path.home() / '.local' / 'state' / 'guardian'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError('Guardian state directory must be owned by the current user and not a symlink')
    root.chmod(0o700)
    path = root / name
    if path.is_symlink():
        raise ValueError('Guardian state file must not be a symlink')
    if path.exists():
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError('Guardian state file must be a regular file owned by the current user')
        path.chmod(0o600)
    return str(path)
