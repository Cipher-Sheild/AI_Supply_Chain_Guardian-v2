import pytest
from app.schema import Finding
from app.scoring import RiskScorer

def test_scoring_invariant_without_hard_block():
    # Create 5 critical findings without hard_block=True
    findings = [
        Finding(
            detector_id=f"DSG-D00{i}",
            file_path="Dockerfile",
            line_number=i,
            preview=f"finding {i}",
            confidence=1.0,
            severity="critical",
            reason=f"Reason {i}",
            remediation="Fix",
            sources=[f"custom:DSG-D00{i}"],
            hard_block=False
        ) for i in range(1, 6)
    ]

    score, status, max_sev = RiskScorer.calculate_score(findings)

    # Invariant check: Raw sum would be 5 * 50 = 250, but without hard_block, must be capped at 89!
    assert score == 89
    assert score < 90
    assert status == "warn"

def test_scoring_with_hard_block():
    findings = [
        Finding(
            detector_id="DSG-C001",
            file_path="docker-compose.yml",
            line_number=1,
            preview="privileged: true",
            confidence=1.0,
            severity="critical",
            reason="Privileged mode enabled",
            remediation="Remove privileged: true",
            sources=["custom:DSG-C001"],
            hard_block=True
        )
    ]

    score, status, max_sev = RiskScorer.calculate_score(findings)
    assert score == 100
    assert status == "fail"
    assert max_sev == "critical"
