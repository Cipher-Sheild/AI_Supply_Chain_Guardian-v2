import pytest
from app.main import derive_status

class MockFinding:
    def __init__(self, severity: str):
        self.severity = severity

def test_derive_status_no_findings():
    assert derive_status([]) == "pass"

def test_derive_status_low_findings():
    findings = [MockFinding("low")]
    assert derive_status(findings) == "warn"

def test_derive_status_mixed_low_medium():
    findings = [MockFinding("low"), MockFinding("medium")]
    assert derive_status(findings) == "warn"

def test_derive_status_high_finding():
    findings = [MockFinding("low"), MockFinding("high")]
    assert derive_status(findings) == "fail"

def test_derive_status_critical_finding():
    findings = [MockFinding("medium"), MockFinding("critical")]
    assert derive_status(findings) == "fail"
