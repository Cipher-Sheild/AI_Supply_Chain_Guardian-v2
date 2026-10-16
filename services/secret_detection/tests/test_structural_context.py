import pytest
from app.detectors.structural_context import StructuralContextDetector

def test_connection_string():
    detector = StructuralContextDetector()
    text = 'DATABASE_URL="postgres://admin:superSecret@!@localhost:5432/db"'
    findings = list(detector.scan(text, "config.env"))
    
    # Wait, the conn string could match both a connection string and an assignment.
    conn_findings = [f for f in findings if f['detector_id'] == 'structural:connection_string']
    assert len(conn_findings) == 1
    assert conn_findings[0]['secret_value'] == 'superSecret@!'

def test_keyword_assignment():
    detector = StructuralContextDetector()
    text = 'DB_PASSWORD = "my_secure_password"'
    findings = list(detector.scan(text, "settings.py"))
    
    kw_findings = [f for f in findings if f['detector_id'] == 'structural:keyword_assignment']
    assert len(kw_findings) == 1
    assert kw_findings[0]['secret_value'] == 'my_secure_password'
