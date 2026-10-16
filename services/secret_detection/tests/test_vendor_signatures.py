import pytest
from app.detectors.vendor_signatures import VendorSignatureDetector
from _fixture_values import STRIPE_KEY

def test_aws_access_key():
    detector = VendorSignatureDetector()
    text = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
    findings = list(detector.scan(text, "test.py"))
    assert len(findings) == 1
    assert findings[0]['detector_id'] == 'vendor_signature:aws_access_key'
    assert findings[0]['secret_value'] == 'AKIAIOSFODNN7EXAMPLE'

def test_stripe_key():
    detector = VendorSignatureDetector()
    text = f'const key = "{STRIPE_KEY}"'
    findings = list(detector.scan(text, "test.js"))
    assert len(findings) == 1
    assert findings[0]['detector_id'] == 'vendor_signature:stripe_key'

def test_openai_key():
    detector = VendorSignatureDetector()
    text = 'sk-proj-d9Z850kEnydx9qWCA79ISjs8JHUdKF0j7elKPoh3pKMzKG5m'
    findings = list(detector.scan(text, "test.py"))
    assert len(findings) == 1
    assert findings[0]['detector_id'] == 'vendor_signature:openai_key'
