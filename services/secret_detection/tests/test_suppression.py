import pytest
from app.detectors.suppression import SuppressionFilter

def test_suppression():
    sf = SuppressionFilter()
    
    # 1. Short string
    is_suppressed, _ = sf.evaluate({"secret_value": "short", "file_path": "test.py"})
    assert is_suppressed is True
    
    # 2. Placeholder
    is_suppressed, _ = sf.evaluate({"secret_value": "this_is_a_test_password", "file_path": "test.py"})
    assert is_suppressed is True
    
    # 3. Valid secret
    is_suppressed, _ = sf.evaluate({"secret_value": "aRealSecretValue123!", "file_path": "test.py"})
    assert is_suppressed is False
    
    # 4. Known public example nuance
    finding = {"secret_value": "AKIAIOSFODNN7EXAMPLE", "file_path": "test.py", "confidence_boost": 95.0}
    is_suppressed, modified_finding = sf.evaluate(finding)
    assert is_suppressed is False
    assert modified_finding["confidence_boost"] <= 30.0
    # 5. URL suppression
    is_suppressed, _ = sf.evaluate({"secret_value": "https://api.openai.com/v1", "file_path": "test.py"})
    assert is_suppressed is True
    
    # 6. URL with credentials should NOT be suppressed
    is_suppressed, _ = sf.evaluate({"secret_value": "https://user:pass@api.openai.com/v1", "file_path": "test.py"})
    assert is_suppressed is False


def test_claimed_fixture_filename_does_not_suppress_explicit_credentials():
    sf=SuppressionFilter();sf.allowlist['allowed_paths']=['tests/fixtures/decoy.txt']
    for context in ('vendor_regex','keyword_assignment','connection_string'):
        suppressed,_=sf.evaluate({'secret_value':'RealCredentialShapedValue123','file_path':'tests/fixtures/decoy.txt','match_context':context})
        assert not suppressed


def test_known_public_example_substring_does_not_downgrade_different_secret():
    sf=SuppressionFilter()
    finding={'secret_value':'AKIAIOSFODNN7EXAMPLE'+'A1b2C3d4E5f6G7h8I9j0','file_path':'app.py','confidence_boost':95.0,'match_context':'keyword_assignment'}
    suppressed,result=sf.evaluate(finding)
    assert not suppressed and result['confidence_boost']==95
