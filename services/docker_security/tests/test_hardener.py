import pytest
from app.harden import DockerfileHardener

BAD_DOCKERFILE = """
FROM ubuntu
RUN apt-get update && apt-get install -y curl
RUN chmod 777 /app/script.sh
CMD ["/app/script.sh"]
"""

def test_dockerfile_hardener_transformations():
    hardener = DockerfileHardener()
    result = hardener.harden(BAD_DOCKERFILE, original_findings_count=4)

    assert result.hardened != BAD_DOCKERFILE
    assert "FROM ubuntu" in result.hardened
    assert "--no-install-recommends" in result.hardened
    assert "chmod 777" in result.hardened
    assert "USER appuser" in result.hardened
    assert "HEALTHCHECK" not in result.hardened
    assert result.verification_passed is False
    assert result.verification_kind == "suggested"
    assert len(result.applied_rules) >= 2
