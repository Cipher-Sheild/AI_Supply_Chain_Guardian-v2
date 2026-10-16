import pytest
from app.schema import Finding
from app.normalize import FindingsNormalizer

def test_deduplication_and_sources_merging():
    # Hadolint, Trivy, and Custom rule reporting untagged image on line 1
    f1 = Finding(
        detector_id="hadolint:DL3007",
        file_path="Dockerfile",
        line_number=1,
        preview="Using latest is prone to errors",
        confidence=1.0,
        severity="medium",
        reason="Hadolint DL3007",
        remediation="Pin tag",
        sources=["hadolint:DL3007"]
    )
    f2 = Finding(
        detector_id="trivy:DS-0001",
        file_path="Dockerfile",
        line_number=1,
        preview="Specify a tag in FROM",
        confidence=1.0,
        severity="medium",
        reason="Trivy DS-0001",
        remediation="Pin tag",
        sources=["trivy:DS-0001"]
    )
    f3 = Finding(
        detector_id="custom:DSG-D002",
        file_path="Dockerfile",
        line_number=1,
        preview="Base image untagged/latest",
        confidence=1.0,
        severity="medium",
        reason="Custom DSG-D002",
        remediation="Pin tag",
        sources=["custom:DSG-D002"]
    )

    deduped = FindingsNormalizer.normalize_and_deduplicate([f1, f2, f3])
    assert len(deduped) == 1

    canonical = deduped[0]
    assert "hadolint:DL3007" in canonical.sources
    assert "trivy:DS-0001" in canonical.sources
    assert "custom:DSG-D002" in canonical.sources
