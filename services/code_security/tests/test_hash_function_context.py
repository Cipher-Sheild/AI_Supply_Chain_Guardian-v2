import pytest
from app.native_python import scan_python

@pytest.mark.parametrize('function,argument,expected',[
 ('password_digest','value',True),('digest','password',True),('checksum','data',False)
])
def test_weak_hash_password_context(function,argument,expected):
 source=f'import hashlib\ndef {function}({argument}):\n    return hashlib.md5({argument}.encode()).hexdigest()\n'
 assert any(f.category=='weak_auth' for f in scan_python(source,'digest.py'))==expected

def test_password_context_does_not_leak_to_next_function():
 source='import hashlib\ndef password_digest(value):\n    return hashlib.sha256(value.encode()).hexdigest()\ndef checksum(data):\n    return hashlib.md5(data).hexdigest()\n'
 assert not scan_python(source,'digest.py')
