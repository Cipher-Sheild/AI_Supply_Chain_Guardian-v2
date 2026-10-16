from app.parsing import ComposeParser,DockerfileParser
from app.rules import ComposeRulesEngine,DockerfileRulesEngine


def test_long_form_bind_mount_detected():
    content='services:\n  app:\n    volumes:\n      - type: bind\n        source: /etc\n        target: /host\n'
    assert any(f.detector_id=='DSG-C003' for f in ComposeRulesEngine().evaluate(ComposeParser(content)))


def test_target_port_detected_even_on_nonstandard_host_port():
    for content in ['services:\n  db:\n    ports: ["15432:5432"]\n',
        'services:\n  db:\n    ports:\n      - target: 5432\n        published: "15432"\n        host_ip: 0.0.0.0\n']:
        assert any(f.detector_id=='DSG-C008' for f in ComposeRulesEngine().evaluate(ComposeParser(content)))


def test_long_form_loopback_and_named_socket_volume_not_host_escape():
    content='services:\n  db:\n    volumes: ["docker.sock-data:/var/data"]\n    ports:\n      - target: 5432\n        published: "15432"\n        host_ip: 127.0.0.1\n'
    ids={f.detector_id for f in ComposeRulesEngine().evaluate(ComposeParser(content))}
    assert not {'DSG-C008','DSG-C002'} & ids


def test_root_with_nonroot_group_and_deferred_build_trigger():
    findings=DockerfileRulesEngine().evaluate(DockerfileParser('FROM alpine:3.20\nONBUILD RUN echo trigger\nUSER 0:10001\n'))
    assert {'DSG-D001','DSG-D014'} <= {f.detector_id for f in findings}
