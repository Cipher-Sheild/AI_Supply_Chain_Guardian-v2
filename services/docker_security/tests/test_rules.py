import pytest
from app.parsing import DockerfileParser, ComposeParser
from app.rules import DockerfileRulesEngine, ComposeRulesEngine

def test_dockerfile_rules_root_and_secret():
    df_content = """
    FROM ubuntu:latest
    ENV AWS_SECRET_ACCESS_KEY="AKIA1234567890abcdef"
    RUN curl http://example.com/install.sh | sh
    EXPOSE 2375
    """
    parser = DockerfileParser(df_content)
    engine = DockerfileRulesEngine()
    findings = engine.evaluate(parser)

    detector_ids = [f.detector_id for f in findings]
    assert "DSG-D001" in detector_ids  # Final stage runs as root
    assert "DSG-D002" in detector_ids  # Base image untagged/latest
    assert "DSG-D003" in detector_ids  # Secret in ENV
    assert "DSG-D004" in detector_ids  # Remote script pipe to shell
    assert "DSG-D006" in detector_ids  # Expose port 2375 (Hard block)

    hard_blocks = [f for f in findings if f.hard_block]
    assert len(hard_blocks) >= 1

def test_compose_rules_privileged_and_sock():
    compose_content = """
    version: '3.8'
    services:
      bad_service:
        image: app:latest
        privileged: true
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
        network_mode: host
        ports:
          - "5432:5432"
    """
    parser = ComposeParser(compose_content)
    engine = ComposeRulesEngine()
    findings = engine.evaluate(parser)

    detector_ids = [f.detector_id for f in findings]
    assert "DSG-C001" in detector_ids  # privileged: true
    assert "DSG-C002" in detector_ids  # docker.sock
    assert "DSG-C004" in detector_ids  # network_mode: host
    assert "DSG-C008" in detector_ids  # sensitive db port published

    # Hard block check
    hard_blocks = [f for f in findings if f.hard_block]
    assert len(hard_blocks) >= 2
