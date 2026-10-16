import os
import time
import pytest
from app.scorer import SecretScorer
from _fixture_values import render_fixture

def get_findings_for_fixture(filename: str):
    fixture_path = os.path.join(os.path.dirname(__file__), filename)
    with open(fixture_path, 'r', encoding='utf-8') as f:
        content = render_fixture(f.read())

    scorer = SecretScorer()
    start_time = time.time()
    findings = scorer.score_findings(content, fixture_path)
    exec_time_ms = (time.time() - start_time) * 1000
    
    return findings, exec_time_ms

def test_integration_flat():
    findings, exec_time_ms = get_findings_for_fixture('sample_secrets_flat.py')
    print(f"\nExecution time (flat): {exec_time_ms:.2f} ms")
    assert exec_time_ms < 500.0, "Execution took too long!"

    found_secrets = set(f.preview for f in findings)
    found_secrets_lower = [f.preview.lower() for f in findings]
    
    # Decoys NOT found
    assert not any("test" in s for s in found_secrets_lower), "Decoy TEST_KEY found!"
    assert not any("database_connection_helper" in s for s in found_secrets_lower), "Decoy NORMAL_VAR found!"

    # Assert redaction rule
    for f in findings:
        assert "***" in f.preview, f"Preview not redacted: {f.preview}"

    assert len(findings) >= 9, f"Expected at least 9 findings, got {len(findings)}"

    # Check for specific vendors catching the secrets
    detector_ids = [f.detector_id for f in findings]
    assert "vendor_signature:openai_key" in detector_ids, "OpenAI key not caught by Layer A!"

def test_integration_realistic():
    findings, exec_time_ms = get_findings_for_fixture('sample_secrets_realistic.py')
    print(f"\nExecution time (realistic): {exec_time_ms:.2f} ms")
    assert exec_time_ms < 500.0, "Execution took too long!"

    found_secrets_lower = [f.preview.lower() for f in findings]
    
    # Decoys NOT found
    assert not any("test" in s for s in found_secrets_lower), "Decoy TEST_KEY found!"
    assert not any("database_connection_helper" in s for s in found_secrets_lower), "Decoy NORMAL_VAR found!"
    assert not any("us-east-1" in s for s in found_secrets_lower), "Decoy REGION found!"
    assert not any("10" in s for s in found_secrets_lower), "Decoy pool_size found!"
    
    # Ensure standard URLs without credentials are not found (false positive suppression)
    assert not any("api.openai.com/v1" in s for s in found_secrets_lower), "False positive on base_url!"

    # Assert redaction rule
    for f in findings:
        assert "***" in f.preview, f"Preview not redacted: {f.preview}"

    assert len(findings) >= 9, f"Expected at least 9 findings, got {len(findings)}"

    # Check for specific vendors catching the secrets
    detector_ids = [f.detector_id for f in findings]
    assert "vendor_signature:openai_key" in detector_ids, "OpenAI key not caught by Layer A!"
