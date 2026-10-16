import io
import zipfile

import pytest

from scripts.package_project import verify_package_input


def test_rejects_private_credential_inside_compressed_extension():
    secret = b'private-deployment-credential-example'
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('extension/dist/extension.js', secret)
    with pytest.raises(ValueError, match='Configured private credential'):
        verify_package_input('guardian.vsix', stream.getvalue(), {secret})


def test_allows_secret_pattern_fixtures_but_rejects_private_key_payload():
    verify_package_input('rules.json', b'-----BEGIN PRIVATE KEY-----', set())
    key = b'-----BEGIN PRIVATE KEY-----\n' + b'A' * 80 + b'\n-----END PRIVATE KEY-----'
    with pytest.raises(ValueError, match='Private key material'):
        verify_package_input('private.pem', key, set())
